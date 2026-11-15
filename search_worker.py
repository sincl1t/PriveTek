"""Run one report consumer per process."""
import signal
from threading import Event

import account_crypto
import job_store
import search_queue
from server import Submission, logger, process_report


def run_one():
    order = search_queue.claim()
    if not order:
        return False
    job_id, token = order['job_id'], order['lease_token']

    def record(status):
        search_queue.record(job_id, token, status)

    try:
        submission = Submission.model_validate_json(account_crypto.report_cipher().decrypt(bytes(order['payload'])))
    except Exception as error:
        logger.error('job=%s queue_payload_failed=%s', job_id, type(error).__name__)
        record('failed')
    else:
        process_report(submission, job_id, record)
    return True


def main():
    if not search_queue.enabled():
        raise SystemExit('SEARCH_QUEUE_ENABLED must be true')
    account_crypto.validate_settings()
    search_queue.validate_settings()
    job_store.initialize()
    logger.info('search_worker_ready')
    stop = Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    while not stop.is_set():
        try:
            if run_one():
                continue
        except Exception as error:
            logger.error('queue_worker_failed=%s', type(error).__name__)
        stop.wait(1)
    logger.info('search_worker_stopped')


if __name__ == '__main__':
    main()
