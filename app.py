"""ThreatConnect Job App"""
# standard library
import json
import time
import datetime
import math
from urllib.parse import urlparse

# first-party
from job_app import JobApp  # Import default Job App Class (Required)

from tcex.batch import Batch
from tcex.sessions import ExternalSession


class App(JobApp):
    """Job App"""

    verbose: bool = False
    retryCount: int = 5
    sleepTime: int = 60

    maxFetchHours = 24
    minFetchHours = 2
    uriMaxLen = 500

    now = None
    last_run = None
    interval: int = 0

    def info(self, msg: str = ""):
        self.tcex.log.info(msg)
        if self.verbose:
            print(msg)

    def __init__(self, _tcex):
        """Initialize class properties."""
        super().__init__(_tcex)

        # properties
        self.batch: Batch = self.tcex.batch(self.args.tc_owner)
        self.rl_api_user: str = self.args.rl_api_user
        self.rl_api_password: str = self.args.rl_api_password

        try:
            self.verbose: bool = bool(int(self.args.verbose))
        except Exception as e:
            self.info(f"{e}")

        if self.verbose:
            self.info(f"{self.args}")

        self.now = datetime.datetime.utcnow()
        try:
            if self.args.last_run:
                # if a run prematurely ends the next run will not have last_run set,
                #    so we directly set it back
                self.tcex.results_tc('last_run', self.args.last_run)
                self.last_run = datetime.datetime.strptime(
                    self.args.last_run, "%Y-%m-%dT%H:%M:%S"
                )  # format: 2021-09-02T16:32:12
        except Exception as e:
            self.info(f"{e}")
            self.last_run = None

        if self.last_run:
            self.interval = int(math.ceil((self.now - self.last_run).total_seconds() / 3600))
        else:
            self.interval = self.maxFetchHours

        # minimal interval = minFetchHours hours, maximal interval is maxFetchHours hours
        if self.interval > self.maxFetchHours:
            self.interval = self.maxFetchHours

        if self.interval < self.minFetchHours:
            self.interval = self.minFetchHours

        msg: str = f"last run: {self.last_run} now: {self.now} diff: {self.interval}"
        self.info(msg)

        self.session = None

    def setup(self):
        """
        Perform prep/setup logic.
        """
        # using tcex session_external to get built-in features (e.g., proxy, logging, retries)
        self.session: ExternalSession = self.tcex.session_external

        # setting the base url allow for subsequent API call to be made by only
        # providing the API endpoint/path.
        self.session.base_url: str = "https://data.reversinglabs.com"

    def getData(self, s, appUri: str):

        n: int = 0
        while n < self.retryCount:
            r = s.get(appUri, verify=True, auth=(self.rl_api_user, self.rl_api_password))
            if r.ok:
                decoded_content: str = r.content.decode('utf-8')
                data = json.loads(decoded_content)
                return data

            n += 1
            msg: str = f"download failed retry {n}, sleeping {self.sleepTime} seconds"
            self.tcex.log.warning(msg)
            time.sleep(self.sleepTime)

        self.tcex.exit(1, "Failed to download data.")

    def runOneRow(self, row, what):

        indicator_type: str = row["indicatorType"]

        # ---------------------------------------
        if indicator_type not in what:
            msg: str = f"type not supported: {indicator_type};{row}"
            self.info(msg)
            return

        try:
            if row["deleted"] is True:
                return

            if "lastUpdate" in row:
                # 'lastUpdate': '2021-09-03T09:08:23.388178Z'
                lastUpdate = row["lastUpdate"]
                lu = datetime.datetime.strptime(lastUpdate[:19], "%Y-%m-%dT%H:%M:%S")
                if self.last_run and self.last_run > lu:
                    self.info(f"SKIP: last_run {self.last_run} > row.lastUpdate: {lu}")
                    return

        except Exception as e:
            self.info(f"ignoring issues in early skip test: {e}")

        # ---------------------------------------
        msg: str = f"processing row: {row}"
        self.info(msg)

        # extract data
        name: str = what[indicator_type]
        indicator_value: str = row["indicatorValue"]
        indicator_tags: str = row["indicatorTags"]
        rating: str = row["rating"]
        confidence: str = row["confidence"]

        if name == "URL":
            if len(indicator_value) > self.uriMaxLen:
                self.info(f"ignoring uri with value len > maxUriLen:500: {indicator_value}")
                return

            # if needed convert the front domain part to lowercase
            zz = urlparse(indicator_value)
            if zz.netloc.lower() != zz.netloc:
                ll = zz.netloc.lower()
                zz = zz._replace(netloc=ll)
                indicator_value = zz.geturl()

        # make a xid from the iType and iValue so we can update the same indicator
        xid: str = f"{indicator_type}.{indicator_value}"

        # create the batch entry
        item: object = self.batch.indicator(
            name,
            indicator_value,
            rating=rating,
            confidence=confidence,
            xid=xid,
        )

        # add all taga
        for tag in indicator_tags:
            item.tag(tag)

        # save object to disk, for large batches this saved memory, says the manual
        self.batch.save(item)

    def run(self):
        """Run main App logic."""

        msg: str = "run start"
        self.info(msg)

        s: str = 'now'
        dd = self.tcex.utils.datetime.format_datetime(self.now.strftime("%Y-%m-%dT%H:%M:%S"))
        msg = f"{s} {dd}"
        self.info(msg)

        # the default
        # appUri: str = f"/api/public/v1/ransomware/indicators?hours={self.interval}"

        iTypes = [
            "Hash",
            "ipv4",
            "domain",
            "uri",
        ]
        siTypes = ",".join(iTypes)

        zz = [
            f"hours={self.interval}",
            f"indicatorTypes={siTypes}",
        ]

        zzs = "&".join(zz)

        appUri: str = f"/api/public/v1/ransomware/indicators?{zzs}"

        msg: str = f"url: {self.session.base_url}{appUri}"
        self.info(msg)

        what = {
            "Hash": "File",
            "ipv4": "Address",
            "domain": "Host",
            "uri": "URL",
        }

        with self.session as s:
            data = self.getData(s, appUri)
            for row in data["data"]:
                self.runOneRow(row, what)

        # submit batch job
        batch_status: list = self.batch.submit_all()

        msg: str = f"batch_status: {batch_status}"
        self.info(msg)

        k: str = "errors"
        for x in batch_status:
            if k in x:
                for item in x[k]:
                    self.info(item)

        last_run = self.now.strftime("%Y-%m-%dT%H:%M:%S")
        # record the timestapm of the last successfull run
        self.tcex.results_tc('last_run', last_run)

        msg: str = f"last_run {last_run}"
        self.info(msg)

        self.exit_message = 'Downloaded data and create batch job.'  # pylint: disable=attribute-defined-outside-init

        msg: str = "run end"
        self.info(msg)
