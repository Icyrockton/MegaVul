import multiprocessing
from vul4c.util.storage import StorageLocation
from datetime import datetime
import logging
from multiprocessing.queues import Queue
from logging.handlers import QueueHandler
from vul4c.util.config import config_file

__all__ = ['global_logger', 'get_child_logger', 'Vul4CLogger']

class Vul4CLogger:

    def __init__(self):
        logger = logging.getLogger('Vul4C')
        logger.setLevel(logging.getLevelNamesMapping()[config_file['log_level']])

        # logging file
        logging_dir = StorageLocation.logging_dir()
        log_file_formatter = logging.Formatter('%(asctime)s - %(filename)s:%(lineno)d - [%(levelname)s]: %(message)s',
                                               datefmt='%m/%d/%Y %I:%M:%S %p')
        file_handler = logging.FileHandler(logging_dir / datetime.now().strftime('log_%Y-%m-%d_%H_%M.log'), mode='w',
                                           encoding='utf-8')
        file_handler.setFormatter(log_file_formatter)

        # console
        console_formatter = logging.Formatter('%(asctime)s - [%(levelname)s]: %(message)s',
                                              datefmt='%m/%d/%Y %I:%M:%S %p')
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(console_formatter)

        # add handlers to logger
        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)

        self.logger = logger

    def get_logger(self):
        return self.logger

    """
        for multiprocessing child process used
    """

    @staticmethod
    def get_child_logger(queue: Queue, logger_name:str) -> logging.Logger:
        logger = multiprocessing.get_logger()
        logger.addHandler(QueueHandler(queue))
        logger.setLevel(logging.getLevelNamesMapping()[config_file['log_level']])
        return logger


global_logger = Vul4CLogger().get_logger()
get_child_logger = Vul4CLogger.get_child_logger
