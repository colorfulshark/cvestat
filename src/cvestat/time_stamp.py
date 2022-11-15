from datetime import datetime
from datetime import timedelta

class Timestamp:
    def __init__(self):
        self.form = '%Y-%m-%dT%H:%M:%S:000 UTC'
        self.initts = '1995-02-25T00:00:00:000 UTC'

    def get_now(self):
        now = datetime.strftime(datetime.utcnow(), self.form)
        return now

    def get_min_datetime(self):
        return datetime(1995, 1, 1)

    def get_max_datetime(self):
        return datetime(2099, 12, 30)

    def get_interval_min(self, ts1, ts2):
        if(ts1 == ''):
            ts1 = self.initts
        if(ts2 == ''):
            ts2 = self.initts
        t1 = datetime.strptime(ts1, self.form)
        t2 = datetime.strptime(ts2, self.form)
        # interval has 'datetime.timedelta' type
        interval = t2 - t1
        return int(interval.total_seconds() / 60)

    def jump_days(self, ts, d):
        dt = datetime.strptime(ts, self.form)
        new_dt = dt + timedelta(days=d)
        return datetime.strftime(new_dt, self.form)

    def cmp(self, ts1, ts2):
        dt1 = datetime.strptime(ts1, self.form)
        dt2 = datetime.strptime(ts2, self.form)
        return (dt1 - dt2).total_seconds()

    def cvt_to_utc(self, ts, form):
        return datetime.strptime(ts, form).strftime(self.form)

    def get_datetime(self, str, form):
        return datetime.strptime(str, form)