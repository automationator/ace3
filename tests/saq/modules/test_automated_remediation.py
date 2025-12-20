import pytest
from unittest.mock import patch
from saq.analysis import RootAnalysis
from saq.configuration.config import get_analysis_module_config
from saq.constants import ANALYSIS_MODULE_AUTOMATED_REMEDIATION, F_EMAIL_DELIVERY
from saq.modules.remediation import AutomatedRemediationAnalyzer
from saq.modules.adapter import AnalysisModuleAdapter
from saq.remediation.target import RemediationTarget

@pytest.mark.unit
def test_automated_remediation_analyzer(test_context):
    # run the automated remediation analyzer on an email delivery observable
    observable = RootAnalysis().add_observable_by_spec(F_EMAIL_DELIVERY, '<test>|jdoe@company.com')
    
    # create the expected remediation target
    expected_target = RemediationTarget('email', F_EMAIL_DELIVERY, '<test>|jdoe@company.com')
    
    # patch get_observable_remediation_targets to return the expected target
    with patch('saq.modules.remediation.get_observable_remediation_targets', return_value=[expected_target]):
        analyzer = AnalysisModuleAdapter(AutomatedRemediationAnalyzer(
            context=test_context,
            config=get_analysis_module_config(ANALYSIS_MODULE_AUTOMATED_REMEDIATION)))
        analyzer.execute_analysis(observable)
    
    analysis = observable.get_analysis(analyzer.generated_analysis_type)

    # verify analysis is correct
    assert analysis.details['targets'][0]['name'] == 'email'
    assert analysis.details['targets'][0]['type'] == F_EMAIL_DELIVERY
    assert analysis.details['targets'][0]['value'] == '<test>|jdoe@company.com'

    # verify remediation table is correct
    target = RemediationTarget('email', F_EMAIL_DELIVERY, '<test>|jdoe@company.com')
    assert target.get_current_remediation()
