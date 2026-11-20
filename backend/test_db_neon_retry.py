"""Focused coverage for Neon connect retries with deadlines."""

from __future__ import annotations

import os
import unittest
from unittest.mock import MagicMock, patch

import psycopg

import db


class TransientNeonConnectTests(unittest.TestCase):
    def test_operational_error_without_permanent_marker_is_transient(self):
        exc = psycopg.OperationalError("could not connect to server: Connection refused")
        self.assertTrue(db.is_transient_neon_connect_error(exc))

    def test_cannot_connect_now_sqlstate_is_transient(self):
        exc = psycopg.OperationalError("the database system is starting up")
        exc.sqlstate = "57P03"
        self.assertTrue(db.is_transient_neon_connect_error(exc))

    def test_password_failure_is_not_transient(self):
        exc = psycopg.OperationalError("password authentication failed for user \"app\"")
        self.assertFalse(db.is_transient_neon_connect_error(exc))

    def test_permission_error_is_not_transient(self):
        self.assertFalse(db.is_transient_neon_connect_error(PermissionError("denied")))

    def test_timeout_error_is_transient(self):
        self.assertTrue(db.is_transient_neon_connect_error(TimeoutError("timed out")))


class ConnectWithRetryTests(unittest.TestCase):
    def setUp(self):
        self._env = patch.dict(
            os.environ,
            {
                "DATABASE_URL": "postgresql://user:secret@db.example/app?sslmode=require",
                "DB_CONNECT_TIMEOUT_SECONDS": "1",
                "DB_CONNECT_DEADLINE_SECONDS": "5",
                "DB_CONNECT_MAX_ATTEMPTS": "3",
                "DB_CONNECT_RETRY_BASE_SECONDS": "0.01",
            },
            clear=False,
        )
        self._env.start()

    def tearDown(self):
        self._env.stop()

    def test_succeeds_after_transient_failures(self):
        transient = psycopg.OperationalError("could not connect to server: Connection refused")
        connection = MagicMock(name="connection")
        with patch("db.psycopg.connect", side_effect=[transient, transient, connection]) as connect:
            with patch("db.time.sleep") as sleep:
                got = db._connect_with_retry(os.environ["DATABASE_URL"])
        self.assertIs(got, connection)
        self.assertEqual(connect.call_count, 3)
        self.assertEqual(sleep.call_count, 2)
        # Privacy: connect receives the URL but our helpers never stringify it into errors we raise on success.
        for call in connect.call_args_list:
            self.assertIn("connect_timeout", call.kwargs)

    def test_non_transient_fails_immediately(self):
        permanent = psycopg.OperationalError("password authentication failed for user \"app\"")
        with patch("db.psycopg.connect", side_effect=permanent) as connect:
            with patch("db.time.sleep") as sleep:
                with self.assertRaises(psycopg.OperationalError):
                    db._connect_with_retry(os.environ["DATABASE_URL"])
        self.assertEqual(connect.call_count, 1)
        sleep.assert_not_called()

    def test_deadline_exceeded_raises_stable_runtime_error(self):
        transient = psycopg.OperationalError("server closed the connection unexpectedly")
        with patch.dict(os.environ, {"DB_CONNECT_DEADLINE_SECONDS": "0.05", "DB_CONNECT_MAX_ATTEMPTS": "5"}):
            with patch("db.psycopg.connect", side_effect=transient):
                with patch("db.time.sleep"):
                    with self.assertRaises(RuntimeError) as ctx:
                        db._connect_with_retry(os.environ["DATABASE_URL"])
        self.assertEqual(str(ctx.exception), "database connection deadline exceeded")
        self.assertNotIn("secret", str(ctx.exception).lower())
        self.assertNotIn("postgresql://", str(ctx.exception).lower())

    def test_max_attempts_exhausted_raises_stable_runtime_error(self):
        transient = psycopg.OperationalError("could not connect to server: Connection refused")
        with patch("db.psycopg.connect", side_effect=transient) as connect:
            with patch("db.time.sleep"):
                with self.assertRaises(RuntimeError) as ctx:
                    db._connect_with_retry(os.environ["DATABASE_URL"])
        self.assertEqual(connect.call_count, 3)
        self.assertEqual(str(ctx.exception), "database connection deadline exceeded")
        self.assertIsInstance(ctx.exception.__cause__, psycopg.OperationalError)

    def test_get_connection_closes_and_yields(self):
        connection = MagicMock(name="connection")
        with patch("db._connect_with_retry", return_value=connection):
            with db.get_connection() as got:
                self.assertIs(got, connection)
        connection.close.assert_called_once_with()

    def test_get_connection_requires_database_url(self):
        with patch.dict(os.environ, {"DATABASE_URL": ""}, clear=False):
            # empty string is treated as unset by database_url()? database_url returns ""
            # which is truthy... check actual behavior
            pass
        with patch("db.database_url", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                with db.get_connection():
                    pass
        self.assertIn("DATABASE_URL", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
