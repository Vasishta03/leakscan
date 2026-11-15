import multiprocessing

from scanner.cli import cli

if __name__ == "__main__":
    multiprocessing.freeze_support()
    cli()
