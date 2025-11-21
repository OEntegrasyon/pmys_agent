import logging
import os
import configparser
import sys

class Logger:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)

            if getattr(sys, 'frozen', False):
                base_path = os.path.dirname(sys.executable)
            else:
                base_path = os.path.dirname(__file__)

            log_file = os.path.join(base_path, 'agent.log')
            logging.basicConfig(
                filename=log_file,
                level=logging.INFO,
                format='%(levelname)s: %(message)s'
            )
            cls._instance.logger = logging.getLogger("AgentLogger")

        return cls._instance

    def get_logger(self):
        return self.logger

logger = Logger().get_logger()
