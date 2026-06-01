#!/usr/bin/env python3
"""Slow-running mock script for sandbox timeout testing.

This script deliberately runs longer than the sandbox timeout (8s)
to validate that the engine enforces execution time limits.
"""
import time
import sys

if __name__ == "__main__":
    time.sleep(30)  # Deliberately exceeds the 8s sandbox timeout
    print("This should never be printed because the container will be killed")
