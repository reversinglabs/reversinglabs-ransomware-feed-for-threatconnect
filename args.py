"""Job Args"""
from argparse import ArgumentParser


class Args:
    """Job Args"""

    def __init__(self, parser: ArgumentParser):
        """Initialize class properties."""
        parser.add_argument(
            '--tc_owner',
            help='the tc_owner string',
            required=True,
        )
        parser.add_argument(
            '--rl_api_password',
            help='The ReversingLabs api user',
            required=True,
        )
        parser.add_argument(
            '--rl_api_user',
            help='The ReversingLabs api password',
            required=True,
        )
        parser.add_argument(
            '--verbose',
            help='explicitly ask for a verbose run, useful during manual runs and testing',
            required=False,
        )
