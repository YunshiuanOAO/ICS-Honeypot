import atexit
import signal
import sys

from agent import NodeAgent


def main():
    agent = NodeAgent()

    def shutdown_handler(_signum=None, _frame=None):
        agent.stop()
        if _signum is not None:
            sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    atexit.register(agent.stop)
    try:
        agent.start()
    except Exception as exc:
        print(f"Fatal client error: {exc}")
        agent.stop()
        raise


if __name__ == "__main__":
    main()
