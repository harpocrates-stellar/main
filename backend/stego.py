from __future__ import annotations

import hashlib
import json
import shutil
import struct
import subprocess
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np


MAGIC = b"HRPSTG1"
MAX_PAYLOAD_BYTES = 64 * 1024
BORDER_BLOCK = 6
BORDER_STRIDE = 2


@dataclass(frozen=True)
class VideoInfo:
    width: int
    height: int
    fps: str
    frame_count: int | None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_metadata_hash(metadata: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(metadata)).hexdigest()


def embed_metadata(source_path: Path | str, output_path: Path | str, metadata: dict[str, Any]) -> None:
    ffmpeg = _require("ffmpeg")
    info = _probe_video(source_path)
    payload = _pack_payload(metadata)
    bits = _bytes_to_bits(payload)

    border_capacity = _border_capacity(info.width, info.height) * (info.frame_count or 1)
    lsb_capacity = info.width * info.height * 3 * (info.frame_count or 1)
    if len(bits) > border_capacity and len(bits) > lsb_capacity:
        raise ValueError("metadata payload is larger than the available video steganography capacity")

    process_in = _start_decode(ffmpeg, source_path, info)
    process_out = _start_encode(ffmpeg, output_path, info)
    frame_size = info.width * info.height * 3
    bit_cursor = 0

    try:
        while True:
            raw = process_in.stdout.read(frame_size)
            if not raw:
                break
            if len(raw) != frame_size:
                raise RuntimeError("ffmpeg returned a partial frame")

            frame = np.frombuffer(raw, dtype=np.uint8).copy().reshape((info.height, info.width, 3))
            bit_cursor = _embed_border_bits(frame, bits, bit_cursor)
            _embed_lsb_bits(frame, bits)
            process_out.stdin.write(frame.tobytes())

        process_out.stdin.close()
        decode_status = process_in.wait(timeout=30)
        encode_status = process_out.wait(timeout=30)
        if decode_status != 0:
            raise RuntimeError("ffmpeg failed while decoding the source video")
        if encode_status != 0:
            raise RuntimeError("ffmpeg failed while encoding the steganographic video")
    finally:
        _close_process(process_in)
        _close_process(process_out)


def extract_metadata(source_path: Path | str) -> dict[str, Any] | None:
    ffmpeg = _require("ffmpeg")
    info = _probe_video(source_path)
    process = _start_decode(ffmpeg, source_path, info)
    frame_size = info.width * info.height * 3
    frames: list[np.ndarray] = []

    try:
        for _ in range(info.frame_count or 240):
            raw = process.stdout.read(frame_size)
            if not raw:
                break
            if len(raw) != frame_size:
                break
            frames.append(np.frombuffer(raw, dtype=np.uint8).reshape((info.height, info.width, 3)).copy())
            border_value = _extract_from_border(frames, info.width, info.height)
            if border_value is not None:
                return border_value

        return _extract_from_lsb(frames)
    finally:
        _close_process(process)


def _pack_payload(metadata: dict[str, Any]) -> bytes:
    body = zlib.compress(_canonical_json(metadata), level=9)
    if len(body) > MAX_PAYLOAD_BYTES:
        raise ValueError("metadata payload exceeds the 64 KiB steganography limit")

    checksum = hashlib.sha256(body).digest()
    return MAGIC + struct.pack(">I", len(body)) + checksum + body


def _unpack_payload(data: bytes) -> dict[str, Any] | None:
    if len(data) < len(MAGIC) + 4 + 32 or not data.startswith(MAGIC):
        return None

    size = struct.unpack(">I", data[len(MAGIC) : len(MAGIC) + 4])[0]
    if size > MAX_PAYLOAD_BYTES:
        return None

    checksum_start = len(MAGIC) + 4
    body_start = checksum_start + 32
    body_end = body_start + size
    if len(data) < body_end:
        return None

    checksum = data[checksum_start:body_start]
    body = data[body_start:body_end]
    if hashlib.sha256(body).digest() != checksum:
        return None

    try:
        value = json.loads(zlib.decompress(body).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, zlib.error):
        return None

    return value if isinstance(value, dict) else None


def _canonical_json(metadata: dict[str, Any]) -> bytes:
    return json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _bytes_to_bits(data: bytes) -> list[int]:
    return [(byte >> shift) & 1 for byte in data for shift in range(7, -1, -1)]


def _bits_to_bytes(bits: list[int]) -> bytes:
    out = bytearray()
    for index in range(0, len(bits) - 7, 8):
        value = 0
        for bit in bits[index : index + 8]:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


def _border_positions(width: int, height: int) -> list[tuple[int, int]]:
    positions: list[tuple[int, int]] = []
    for x in range(0, width, BORDER_BLOCK):
        positions.append((BORDER_STRIDE, x))
    for y in range(BORDER_BLOCK, height, BORDER_BLOCK):
        positions.append((y, width - BORDER_STRIDE - 1))
    for x in range(width - BORDER_BLOCK, -1, -BORDER_BLOCK):
        positions.append((height - BORDER_STRIDE - 1, x))
    for y in range(height - BORDER_BLOCK, BORDER_BLOCK - 1, -BORDER_BLOCK):
        positions.append((y, BORDER_STRIDE))
    return positions


def _border_capacity(width: int, height: int) -> int:
    return len(_border_positions(width, height))


def _embed_border_bits(frame: np.ndarray, bits: list[int], cursor: int) -> int:
    height, width, _ = frame.shape
    for y, x in _border_positions(width, height):
        if cursor >= len(bits):
            break
        bit = bits[cursor]
        color = 238 if bit else 17
        y0 = max(0, y - BORDER_STRIDE)
        y1 = min(height, y + BORDER_STRIDE + 1)
        x0 = max(0, x - BORDER_STRIDE)
        x1 = min(width, x + BORDER_STRIDE + 1)
        frame[y0:y1, x0:x1, :] = color
        cursor += 1
    return cursor


def _embed_lsb_bits(frame: np.ndarray, bits: list[int]) -> None:
    flat = frame.reshape(-1)
    limit = min(len(bits), len(flat))
    if limit == 0:
        return
    bit_values = np.asarray(bits[:limit], dtype=np.uint8)
    flat[:limit] = (flat[:limit] & np.uint8(0xFE)) | bit_values


def _extract_from_border(frames: list[np.ndarray], width: int, height: int) -> dict[str, Any] | None:
    bits: list[int] = []
    for frame in frames:
        for y, x in _border_positions(width, height):
            y0 = max(0, y - BORDER_STRIDE)
            y1 = min(height, y + BORDER_STRIDE + 1)
            x0 = max(0, x - BORDER_STRIDE)
            x1 = min(width, x + BORDER_STRIDE + 1)
            bits.append(1 if int(frame[y0:y1, x0:x1, :].mean()) >= 128 else 0)

    return _unpack_progressive(bits)


def _extract_from_lsb(frames: list[np.ndarray]) -> dict[str, Any] | None:
    bits: list[int] = []
    for frame in frames:
        bits.extend(int(value & 1) for value in frame.reshape(-1))
        value = _unpack_progressive(bits)
        if value is not None:
            return value
    return None


def _unpack_progressive(bits: list[int]) -> dict[str, Any] | None:
    header_bits = (len(MAGIC) + 4 + 32) * 8
    if len(bits) < header_bits:
        return None

    header = _bits_to_bytes(bits[:header_bits])
    if not header.startswith(MAGIC):
        return None

    size = struct.unpack(">I", header[len(MAGIC) : len(MAGIC) + 4])[0]
    if size > MAX_PAYLOAD_BYTES:
        return None

    total_bits = (len(MAGIC) + 4 + 32 + size) * 8
    if len(bits) < total_bits:
        return None

    return _unpack_payload(_bits_to_bytes(bits[:total_bits]))


def _probe_video(path: Path | str) -> VideoInfo:
    ffprobe = _require("ffprobe")
    result = subprocess.run(
        [
            ffprobe,
            "-v",
            "error",
            "-select_streams",
            "v:0",
            "-show_entries",
            "stream=width,height,r_frame_rate,nb_frames",
            "-of",
            "json",
            str(path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    streams = json.loads(result.stdout).get("streams", [])
    if not streams:
        raise ValueError("uploaded file does not contain a video stream")

    stream = streams[0]
    frames = stream.get("nb_frames")
    return VideoInfo(
        width=int(stream["width"]),
        height=int(stream["height"]),
        fps=stream.get("r_frame_rate") or "30/1",
        frame_count=int(frames) if str(frames).isdecimal() else None,
    )


def _start_decode(ffmpeg: str, source_path: Path | str, info: VideoInfo) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [
            ffmpeg,
            "-v",
            "error",
            "-i",
            str(source_path),
            "-map",
            "0:v:0",
            "-f",
            "rawvideo",
            "-pix_fmt",
            "rgb24",
            "-",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _start_encode(ffmpeg: str, output_path: Path | str, info: VideoInfo) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [
            ffmpeg,
            "-y",
            "-v",
            "error",
            "-f",
            "rawvideo",
            "-pix_fmt",
            "rgb24",
            "-s",
            f"{info.width}x{info.height}",
            "-r",
            info.fps,
            "-i",
            "-",
            "-an",
            "-c:v",
            "libx264",
            "-preset",
            "medium",
            "-crf",
            "16",
            "-pix_fmt",
            "yuv420p",
            str(output_path),
        ],
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _require(binary: str) -> str:
    found = shutil.which(binary)
    if not found:
        raise RuntimeError(f"{binary} is required for steganography processing")
    return found


def _close_process(process: subprocess.Popen[bytes]) -> None:
    if process.stdin and not process.stdin.closed:
        process.stdin.close()
    if process.stdout and not process.stdout.closed:
        process.stdout.close()
    if process.stderr and not process.stderr.closed:
        process.stderr.close()
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
