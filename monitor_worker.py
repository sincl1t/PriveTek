"""One bounded durable operation per tick. OpenAI and phone searches are never invoked."""
import logging
import monitor_store as store
import monitoring
from account_store import now


def tick():
    store.cleanup()
    mail=store.claim_mail()
    if mail:
        if mail.get('skip'):return {'operation':'notification','status':'cancelled'}
        accepted=False
        try:
            import email_sender
            email_sender.send_monitor_notice(mail['email'])
            accepted=True
        except Exception as error:
            logging.getLogger('privetek').warning('monitor_notice_unconfirmed=%s',type(error).__name__)
        store.finish_mail(mail['id'],accepted)
        return {'operation':'notification','status':'provider_accepted' if accepted else 'delivery_unknown'}
    claim=store.claim_scan()
    if not claim:return {'operation':'idle'}
    try:
        import osint
        data=osint.search(email=claim['email'],username=claim['config']['username'] or None,phone=None)
        observations=monitoring.observe(data)
        excluded=set(claim['config']['excluded'])
        if claim['config'].get('use_profile_reviews',True):
            reviews=store.profile_reviews(claim['email_key'],claim['config']['username'])
            excluded.update(item['id'] for item in observations['items'].values() if item['link_id'] in reviews)
        excluded.difference_update(claim['config'].get('included',[]))
        result=monitoring.compare(claim['baseline'],observations,now(),excluded)
        valid=store.complete_scan(claim,result)
        return {'operation':'scan','status':'recorded' if valid else 'cancelled'}
    except Exception as error:
        logging.getLogger('privetek').warning('monitor_scan_failed=%s',type(error).__name__)
        store.complete_scan(claim)
        return {'operation':'scan','status':'unavailable'}
