from datetime import datetime
import logging
from typing import Optional

from saq.analysis.analysis import Analysis
from saq.analysis.observable import Observable
from saq.analysis.root import RootAnalysis
from saq.engine.configuration_manager import ConfigurationManager
from saq.modules.interfaces import AnalysisModuleInterface


class DelayedAnalysisRequest:
    """Encapsulates a request for delayed analysis."""

    def __init__(
        self,
        uuid: str,
        observable_uuid: str,
        analysis_module_str: str,
        next_analysis: datetime,
        storage_dir: str,
        database_id: Optional[int]=None,
    ):
        assert isinstance(uuid, str) and uuid
        assert isinstance(observable_uuid, str) and observable_uuid
        assert isinstance(analysis_module_str, str) and analysis_module_str
        assert isinstance(storage_dir, str) and storage_dir

        self.uuid = uuid
        self.observable_uuid = observable_uuid
        self.analysis_module_str = analysis_module_str
        self.next_analysis = next_analysis
        self.database_id = database_id
        self.storage_dir = storage_dir

        self.root: Optional[RootAnalysis] = None
        self.observable: Optional[Observable] = None
        self.analysis: Optional[Analysis] = None
        self.analysis_module: Optional[AnalysisModuleInterface] = None

    def load(self, configuration_manager: ConfigurationManager):
        """Loads the root, then loads the observable, analysis_module and analysis objects from the root.
        
        Returns True if everything loaded successfully, False otherwise."""

        logging.debug(f"loading {self}")
        self.root = RootAnalysis(uuid=self.uuid, storage_dir=self.storage_dir)
        self.root.load()

        # get a reference to the observable the delayed analysis is for
        self.observable = self.root.get_observable(self.observable_uuid)
        if self.observable is None:
            logging.error(
                f"unable to load observable {self.observable_uuid} for {self}"
            )
            return False

        # get a reference to the analysis module that delayed the analysis
        self.analysis_module = configuration_manager.get_analysis_module_by_name(self.analysis_module_str)
        if self.analysis_module is None:
            logging.error(f"missing analysis module {self.analysis_module_str} for {self}")
            return False

        # get a reference to the analysis output
        if self.observable is not None and self.analysis_module is not None:
            self.analysis = self.observable.get_analysis(
                self.analysis_module.generated_analysis_type,
                instance=self.analysis_module.instance,
            )
            if self.analysis is None:
                logging.error(
                    f"unable to load analysis {self.analysis_module.generated_analysis_type} for {self}"
                )
                return False

        return True

    def __str__(self):
        return "DelayedAnalysisRequest for {} by {} @ {}".format(
            self.uuid, self.analysis_module_str, self.next_analysis
        )

    def __repr__(self):
        return self.__str__()
