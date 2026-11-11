#!/usr/bin/env python3
"""
User-initiated microphone recorder for DeepfakeShield V10.1.3 voice verification.
Captures 6 seconds of 16,000 Hz Mono PCM16 WAV audio directly from the default microphone
into audio_samples/clean_executive_instruction_fresh.wav without registering or submitting it.
"""

import hashlib
import os
import sys
import wave
from pathlib import Path

import numpy as np
import sounddevice as sd


PROMPT_TEXT = (
    "This is a fresh audio sample recorded directly from my microphone "
    "for the DeepfakeShield Sandbox verification test."
)
TARGET_PATH = Path(__file__).resolve().parent / "audio_samples" / "clean_executive_instruction_fresh.wav"
SAMPLE_RATE = 16000
CHANNELS = 1
DURATION_SEC = 6.0


def main() -> int:
    TARGET_PATH.parent.mkdir(parents=True, exist_ok=True)
    default_idx = sd.default.device[0]
    dev_info = sd.query_devices(default_idx)

    print("=== DeepfakeShield V10.1.3 — Fresh Microphone Capture ===")
    print(f"Input device : [{default_idx}] {dev_info['name']}")
    print(f"Output file  : {TARGET_PATH}")
    print(f"Format       : WAV PCM16 | {SAMPLE_RATE} Hz | {CHANNELS} ch (Mono) | {DURATION_SEC:.1f}s")
    print("\nRead this exact text clearly after pressing ENTER:\n")
    print(f'  "{PROMPT_TEXT}"\n')

    input("Press ENTER to start 6-second microphone recording (Ctrl+C to cancel)...")
    print("Recording now... speak clearly.")
    frames = int(SAMPLE_RATE * DURATION_SEC)
    audio = sd.rec(frames, samplerate=SAMPLE_RATE, channels=CHANNELS, dtype="int16")
    sd.wait()
    print("Recording complete.")

    pcm = np.asarray(audio, dtype=np.int16).reshape(-1)
    rms = float(np.sqrt(np.mean((pcm.astype(np.float32) / 32768.0) ** 2)))
    if rms < 1e-4:
        print("[!] WARNING: Recorded signal amplitude is near zero. Check microphone mute/input device.")

    with wave.open(str(TARGET_PATH), "wb") as wf:
        wf.setnchannels(CHANNELS)
        wf.setsampwidth(2)
        wf.setframerate(SAMPLE_RATE)
        wf.writeframes(pcm.tobytes())

    sha256_hex = hashlib.sha256(TARGET_PATH.read_bytes()).hexdigest()
    print(f"Saved        : {TARGET_PATH}")
    print(f"Samples      : {len(pcm)} ({len(pcm) / SAMPLE_RATE:.2f}s)")
    print(f"RMS Level    : {rms:.4f}")
    print(f"SHA-256      : {sha256_hex}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
