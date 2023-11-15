import logging
import math
import multiprocessing
import random
import time
from multiprocessing.pool import Pool
from multiprocessing.managers import SyncManager
from multiprocessing import Process, current_process
from vul4c.util.config import config_file
from vul4c.util.logging_util import global_logger, get_child_logger
from typing import Callable, TypeVar, Iterable, List
from logging.handlers import QueueHandler

_T = TypeVar("_T")
_S = TypeVar("_S")
_R = TypeVar("_R")
__all__ = ['multiprocessing_apply_data_with_logger','multiprocessing_map']

# https://stackoverflow.com/questions/25539020/python-concurrency-hangs-when-using-apply-async
# https://stackoverflow.com/questions/70465276/multiprocessing-hanging-at-join
def listener_process(queue: multiprocessing.Queue):
    logger = global_logger
    while True:
        message = queue.get()
        if message is None:
            logger.info('listener_process Done')
            break  # shutdown the logger process
        logger.handle(message)  # log the message

def child_process_wrapper(queue: multiprocessing.Queue,
                          inner_func: Callable[[logging.Logger, _T], _S] | Callable[
                              [logging.Logger, List[_T]], List[_S]]
                          , chunk: List[_T], chunk_mode: bool):
    pname, pid = current_process().name,current_process().pid
    logger = logging.getLogger()
    logger.addHandler(QueueHandler(queue))
    logger.setLevel(logging.getLevelNamesMapping()[config_file['log_level']])

    chunk_result = []
    chunk_len = len(chunk)
    prefix_id = f'Multiprocessing {pname} [PID-{pid}]'
    logger.info(f'{prefix_id} Worker Start!')
    if not chunk_mode:
        for idx,item in enumerate(chunk):
            if idx > 100 and idx % int(chunk_len * 0.1) == 0:
                logger.info(f'{prefix_id} [{idx}/{chunk_len}]')
            chunk_result.append(inner_func(logger, item))
    else:
        if (res:= inner_func(logger, chunk)) is not None:
            chunk_result.extend(res)
    logger.info(f'{prefix_id} Worker Done!')
    return chunk_result


# https://gist.github.com/baojie/6047780
# https://superfastpython.com/multiprocessing-pool-logging/
def multiprocessing_apply_data_with_logger(
        func_with_logger: Callable[[logging.Logger, _T], _S] | Callable[[logging.Logger, List[_R]], List[_S]],
        data: List[_T | _R], chunk_mode=False, debug=False) -> List[_S]:
    if debug:
        global_logger.debug('running multiprocessing_apply_data_with_logger in DEBUG mode will run in single process')
        res = []
        if chunk_mode:
            ans = func_with_logger(global_logger,data)
            if ans is not None:
                res.extend(ans)
        else:
            for x in data:
                res.append(func_with_logger(global_logger, x))
        return res

    max_processors = max(min(int(multiprocessing.cpu_count() * 0.75), len(data)), 1)
    chunk_size = math.ceil(len(data) / max_processors)
    chunks = [data[i: i + chunk_size] for i in range(0, len(data), chunk_size)]
    final_result: List[_S] = []
    global_logger.info(f'multiprocessing begin process {len(data)}(chuck size {chunk_size}) items in {max_processors} processors')


    def save_result(result):
        final_result.extend(result)

    sync_manager: SyncManager
    with multiprocessing.Manager() as sync_manager:
        queue = sync_manager.Queue(-1)
        pool: Pool
        with multiprocessing.Pool() as pool:
            _ = pool.apply_async(listener_process, args=(queue,))
            results = [pool.apply_async(child_process_wrapper, args=(queue, func_with_logger, chunks[i], chunk_mode),
                                        callback=save_result) for i in range(len(chunks))]
            for result in results:
                result.get()
            queue.put_nowait(None)  # close flag
            pool.close()
            pool.join()

    return final_result


def wrapper_func(x: _T, func: Callable[[logging.Logger, _T], _S], logger: logging.Logger) -> _S:
    return func(logger, x)

def multiprocessing_map(func:Callable[[_T],_S],data:Iterable[_T]):
    pool: Pool
    with multiprocessing.Pool() as pool:
        res = pool.map(func,data)
        return res

def test_call(logger: logging.Logger, data):
    process_name = current_process().name
    # logger.debug(f'{process_name} hello {data}')

    logger.info(f'[{process_name}] hello {data}')
    time.sleep(random.random())
    # time.sleep(0.1)
    return data * 2


if __name__ == '__main__':
    # multiprocessing_data_with_logger(test_call, list(range(1000)))
    multiprocessing_apply_data_with_logger(test_call, list(range(1000)))
