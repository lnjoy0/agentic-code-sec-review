#!/usr/bin/env python3
import asyncio
import os
import logging
import sys

from sec_reviewer.core import Config
from sec_reviewer import CodeSecReviewer

def validate_environment() -> bool:
    required_vars = ["GITHUB_TOKEN", "GITHUB_EVENT_PATH"]
    missing_vars = []

    for var in required_vars:
        if not os.environ.get(var):
            missing_vars.append(var)
    
    if missing_vars:
        print(f"Error: Missing required environment variables: {', '.join(missing_vars)}")
        return False

    return True

async def main_async() -> int:
    print("Agentic Code Security Reviewer starting...")

    # Validate environment first
    if not validate_environment():
        return 1
    
    try:
        # Load configuration from environment
        config = Config.from_environment()

        # Setup logging based on configuration
        logging.basicConfig(
            level = getattr(logging, config.logging.level),
            format = config.logging.format,
            handlers = [logging.StreamHandler(sys.stdout)]
        )

        # Create code reviewer with configuration
        with CodeSecReviewer(config) as reviewer:
            # Perform the code review
            success = await reviewer.run()

            # Return appropriate exit code
            if success:
                return 0
            else:
                return 1
    except Exception as e:
        print(f"Fatal error during code review: {str(e)}")
        return 1

def main() -> int: 
    try:
        return asyncio.run(main_async())
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
if __name__ == "__main__":
    sys.exit(main())