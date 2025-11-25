import os
import pytest
from unittest.mock import Mock, patch
from subprocess import TimeoutExpired

from saq.constants import F_FILE, AnalysisExecutionResult, R_EXTRACTED_FROM
from saq.modules.file_analysis.dotnet import (
    De4dotAnalysis,
    De4dotAnalyzer,
    IlspyAnalysis,
    IlspyAnalyzer,
    KEY_STDOUT,
    KEY_STDERR,
    KEY_ERROR,
    KEY_DEOBFUSCATED,
    KEY_EXIT_CODE,
)
from saq.observables.file import FileObservable
from tests.saq.test_util import create_test_context
from saq.configuration.config import get_config


@pytest.mark.unit
class TestDe4dotAnalysis:

    def test_init(self):
        analysis = De4dotAnalysis()
        assert analysis.stdout is None
        assert analysis.stderr is None
        assert analysis.error is None
        assert analysis.deobfuscated is False

    def test_display_name(self):
        analysis = De4dotAnalysis()
        assert analysis.display_name == "De4dot Analysis"

    def test_stdout_property(self):
        analysis = De4dotAnalysis()

        # test getter with None
        assert analysis.stdout is None

        # test setter and getter
        test_stdout = "test stdout output"
        analysis.stdout = test_stdout
        assert analysis.stdout == test_stdout
        assert analysis.details[KEY_STDOUT] == test_stdout

    def test_stderr_property(self):
        analysis = De4dotAnalysis()

        # test getter with None
        assert analysis.stderr is None

        # test setter and getter
        test_stderr = "test stderr output"
        analysis.stderr = test_stderr
        assert analysis.stderr == test_stderr
        assert analysis.details[KEY_STDERR] == test_stderr

    def test_error_property(self):
        analysis = De4dotAnalysis()

        # test getter with None
        assert analysis.error is None

        # test setter and getter
        test_error = "test error message"
        analysis.error = test_error
        assert analysis.error == test_error
        assert analysis.details[KEY_ERROR] == test_error

    def test_deobfuscated_property(self):
        analysis = De4dotAnalysis()

        # test getter with False
        assert analysis.deobfuscated is False

        # test setter and getter
        analysis.deobfuscated = True
        assert analysis.deobfuscated is True
        assert analysis.details[KEY_DEOBFUSCATED] is True

    def test_generate_summary_with_error(self):
        analysis = De4dotAnalysis()
        analysis.error = "Deobfuscation failed"

        summary = analysis.generate_summary()
        assert summary == "De4dot Analysis error: Deobfuscation failed"

    def test_generate_summary_success(self):
        analysis = De4dotAnalysis()
        analysis.error = None

        summary = analysis.generate_summary()
        assert summary == "De4dot Analysis: deobfuscated"


@pytest.mark.unit
class TestDe4dotAnalyzer:

    def test_generated_analysis_type(self):
        analyzer = De4dotAnalyzer(context=create_test_context())
        assert analyzer.generated_analysis_type == De4dotAnalysis

    def test_valid_observable_types(self):
        analyzer = De4dotAnalyzer(context=create_test_context())
        assert analyzer.valid_observable_types == F_FILE

    def test_execute_analysis_file_not_exists(self, root_analysis, tmpdir):
        analyzer = De4dotAnalyzer(context=create_test_context(root=root_analysis))

        # create a file observable for non-existent file by first creating it, then adding it, then deleting it
        test_file = tmpdir / "temp.exe"
        test_file.write("temp content")
        file_observable = root_analysis.add_file_observable(str(test_file))
        # now remove the file so it doesn't exist when the analyzer tries to process it
        os.remove(str(test_file))

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

    @patch("saq.modules.file_analysis.dotnet.is_dotnet")
    def test_execute_analysis_not_dotnet_file(self, mock_is_dotnet, root_analysis, tmpdir):
        mock_is_dotnet.return_value = False
        analyzer = De4dotAnalyzer(context=create_test_context(root=root_analysis))

        # create a non-dotnet file
        test_file = tmpdir / "test.txt"
        test_file.write("this is not a dotnet file")

        file_observable = root_analysis.add_file_observable(str(test_file))

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should not have created any analysis
        analysis = file_observable.get_analysis(De4dotAnalysis)
        assert analysis is None

    @patch("saq.modules.file_analysis.dotnet.Popen")
    @patch("saq.modules.file_analysis.dotnet.is_dotnet")
    def test_execute_analysis_no_obfuscation_detected(self, mock_is_dotnet, mock_popen, root_analysis, tmpdir):
        mock_is_dotnet.return_value = True

        # mock the -d detection check to return no obfuscation
        mock_process = Mock()
        mock_process.communicate.return_value = (b"No obfuscation detected", b"")
        mock_popen.return_value = mock_process

        analyzer = De4dotAnalyzer(context=create_test_context(root=root_analysis))

        test_file = tmpdir / "test.exe"
        test_file.write("fake dotnet content")

        file_observable = root_analysis.add_file_observable(str(test_file))

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should not have created any analysis
        analysis = file_observable.get_analysis(De4dotAnalysis)
        assert analysis is None

    @patch("saq.modules.file_analysis.dotnet.Popen")
    @patch("saq.modules.file_analysis.dotnet.is_dotnet")
    def test_execute_analysis_detection_timeout(self, mock_is_dotnet, mock_popen, root_analysis, tmpdir):
        mock_is_dotnet.return_value = True

        # mock the -d detection check to timeout
        mock_process = Mock()
        mock_process.communicate.side_effect = TimeoutExpired(cmd="de4dot", timeout=10)
        mock_process.kill = Mock()
        mock_popen.return_value = mock_process

        analyzer = De4dotAnalyzer(context=create_test_context(root=root_analysis))

        test_file = tmpdir / "test.exe"
        test_file.write("fake dotnet content")

        file_observable = root_analysis.add_file_observable(str(test_file))

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # verify kill was called
        mock_process.kill.assert_called_once()

    @patch("saq.modules.file_analysis.dotnet.Popen")
    @patch("saq.modules.file_analysis.dotnet.is_dotnet")
    def test_execute_analysis_detection_exception(self, mock_is_dotnet, mock_popen, root_analysis, tmpdir):
        mock_is_dotnet.return_value = True

        # mock the -d detection check to raise an exception
        mock_popen.side_effect = Exception("Test exception")

        analyzer = De4dotAnalyzer(context=create_test_context(root=root_analysis))

        test_file = tmpdir / "test.exe"
        test_file.write("fake dotnet content")

        file_observable = root_analysis.add_file_observable(str(test_file))

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should not have created any analysis
        analysis = file_observable.get_analysis(De4dotAnalysis)
        assert analysis is None

    @patch("saq.modules.file_analysis.dotnet.Popen")
    @patch("saq.modules.file_analysis.dotnet.is_dotnet")
    def test_execute_analysis_successful_deobfuscation(self, mock_is_dotnet, mock_popen, root_analysis, tmpdir):
        mock_is_dotnet.return_value = True

        # mock the -d detection check to return obfuscation detected
        mock_detect_process = Mock()
        mock_detect_process.communicate.return_value = (b"Detected obfuscation", b"")

        # mock the deobfuscation process
        mock_deobfuscate_process = Mock()
        mock_deobfuscate_process.communicate.return_value = (b"deobfuscation stdout", b"deobfuscation stderr")

        mock_popen.side_effect = [mock_detect_process, mock_deobfuscate_process]

        analyzer = De4dotAnalyzer(context=create_test_context(root=root_analysis))

        test_file = tmpdir / "test.exe"
        test_file.write("fake dotnet content")

        file_observable = root_analysis.add_file_observable(str(test_file))

        # create the deobfuscated file that would be created by de4dot
        deobfuscated_file = f"{file_observable.full_path}.deobfuscated"
        with open(deobfuscated_file, "w") as f:
            f.write("deobfuscated content")

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should have created analysis
        analysis = file_observable.get_analysis(De4dotAnalysis)
        assert analysis is not None
        assert isinstance(analysis, De4dotAnalysis)

        # check analysis properties
        assert analysis.stdout == "deobfuscation stdout"
        assert analysis.stderr == "deobfuscation stderr"
        assert analysis.error is None
        assert analysis.deobfuscated is True

        # check that deobfuscated file was added as observable
        deobfuscated_observable = None
        for obs in analysis.observables:
            if isinstance(obs, FileObservable) and obs.file_name.endswith(".deobfuscated"):
                deobfuscated_observable = obs
                break

        assert deobfuscated_observable is not None
        assert deobfuscated_observable.has_relationship(R_EXTRACTED_FROM)
        assert deobfuscated_observable.redirection == file_observable

    @patch("saq.modules.file_analysis.dotnet.Popen")
    @patch("saq.modules.file_analysis.dotnet.is_dotnet")
    def test_execute_analysis_deobfuscation_timeout(self, mock_is_dotnet, mock_popen, root_analysis, tmpdir):
        mock_is_dotnet.return_value = True

        # mock the -d detection check to return obfuscation detected
        mock_detect_process = Mock()
        mock_detect_process.communicate.return_value = (b"Detected obfuscation", b"")

        # mock the deobfuscation process to timeout
        mock_deobfuscate_process = Mock()
        mock_deobfuscate_process.communicate.side_effect = TimeoutExpired(cmd="de4dot", timeout=10)
        mock_deobfuscate_process.kill = Mock()

        mock_popen.side_effect = [mock_detect_process, mock_deobfuscate_process]

        analyzer = De4dotAnalyzer(context=create_test_context(root=root_analysis))

        test_file = tmpdir / "test.exe"
        test_file.write("fake dotnet content")

        file_observable = root_analysis.add_file_observable(str(test_file))

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # verify kill was called
        mock_deobfuscate_process.kill.assert_called_once()

        # should have created analysis
        analysis = file_observable.get_analysis(De4dotAnalysis)
        assert analysis is not None
        assert analysis.deobfuscated is True

    @patch("saq.modules.file_analysis.dotnet.Popen")
    @patch("saq.modules.file_analysis.dotnet.is_dotnet")
    def test_execute_analysis_deobfuscation_exception(self, mock_is_dotnet, mock_popen, root_analysis, tmpdir):
        mock_is_dotnet.return_value = True

        # mock the -d detection check to return obfuscation detected
        mock_detect_process = Mock()
        mock_detect_process.communicate.return_value = (b"Detected obfuscation", b"")

        # mock the deobfuscation process to raise an exception
        mock_popen.side_effect = [mock_detect_process, Exception("Test exception")]

        analyzer = De4dotAnalyzer(context=create_test_context(root=root_analysis))

        test_file = tmpdir / "test.exe"
        test_file.write("fake dotnet content")

        file_observable = root_analysis.add_file_observable(str(test_file))

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should have created analysis with error
        analysis = file_observable.get_analysis(De4dotAnalysis)
        assert analysis is not None
        assert analysis.error == "Test exception"
        assert analysis.deobfuscated is True


@pytest.mark.unit
class TestIlspyAnalysis:

    def test_init(self):
        analysis = IlspyAnalysis()
        assert analysis.stderr is None
        assert analysis.exit_code is None

    def test_exit_code_property(self):
        analysis = IlspyAnalysis()

        # test getter with None
        assert analysis.exit_code is None

        # test setter and getter
        analysis.exit_code = 0
        assert analysis.exit_code == 0
        assert analysis.details[KEY_EXIT_CODE] == 0

    def test_stderr_property(self):
        analysis = IlspyAnalysis()

        # test getter with None
        assert analysis.stderr is None

        # test setter and getter
        test_stderr = "test stderr output"
        analysis.stderr = test_stderr
        assert analysis.stderr == test_stderr
        assert analysis.details[KEY_STDERR] == test_stderr

    def test_generate_summary_basic(self):
        analysis = IlspyAnalysis()

        summary = analysis.generate_summary()
        assert summary == "Ilspy Analysis"

    def test_generate_summary_with_exit_code(self):
        analysis = IlspyAnalysis()
        analysis.exit_code = 0

        summary = analysis.generate_summary()
        assert summary == "Ilspy Analysis: exit code 0"

    def test_generate_summary_with_stderr(self):
        analysis = IlspyAnalysis()
        analysis.stderr = "some error message"

        summary = analysis.generate_summary()
        assert summary == "Ilspy Analysis: stderr: some error message"

    def test_generate_summary_with_both(self):
        analysis = IlspyAnalysis()
        analysis.exit_code = 1
        analysis.stderr = "error occurred"

        summary = analysis.generate_summary()
        assert summary == "Ilspy Analysis: exit code 1: stderr: error occurred"


@pytest.mark.unit
class TestIlspyAnalyzer:

    @pytest.fixture
    def ilspy_config(self):
        """fixture to set up ilspy configuration"""
        config = get_config()
        # add the ilspy analyzer config section if it doesn't exist
        if "analysis_module_saq.modules.file_analysis.dotnet:IlspyAnalyzer" not in config:
            config.add_section("analysis_module_saq.modules.file_analysis.dotnet:IlspyAnalyzer")
        config["analysis_module_saq.modules.file_analysis.dotnet:IlspyAnalyzer"]["binary_path"] = "/usr/bin/ilspy"
        return config

    def test_generated_analysis_type(self, ilspy_config):
        analyzer = IlspyAnalyzer(context=create_test_context())
        assert analyzer.generated_analysis_type == IlspyAnalysis

    def test_valid_observable_types(self, ilspy_config):
        analyzer = IlspyAnalyzer(context=create_test_context())
        assert analyzer.valid_observable_types == F_FILE

    def test_binary_path_property(self, ilspy_config):
        analyzer = IlspyAnalyzer(context=create_test_context())
        # just verify the property returns something (it reads from config)
        assert analyzer.binary_path is not None
        assert isinstance(analyzer.binary_path, str)

    def test_execute_analysis_file_not_exists(self, ilspy_config, root_analysis, tmpdir):
        analyzer = IlspyAnalyzer(context=create_test_context(root=root_analysis))

        # create a file observable for non-existent file by first creating it, then adding it, then deleting it
        test_file = tmpdir / "temp.exe"
        test_file.write("temp content")
        file_observable = root_analysis.add_file_observable(str(test_file))
        # now remove the file so it doesn't exist when the analyzer tries to process it
        os.remove(str(test_file))

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

    @patch("saq.modules.file_analysis.dotnet.is_dotnet")
    def test_execute_analysis_not_dotnet_file(self, mock_is_dotnet, ilspy_config, root_analysis, tmpdir):
        mock_is_dotnet.return_value = False

        analyzer = IlspyAnalyzer(context=create_test_context(root=root_analysis))

        # create a non-dotnet file
        test_file = tmpdir / "test.txt"
        test_file.write("this is not a dotnet file")

        file_observable = root_analysis.add_file_observable(str(test_file))

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should not have created any analysis
        analysis = file_observable.get_analysis(IlspyAnalysis)
        assert analysis is None

    @patch("saq.modules.file_analysis.dotnet.Popen")
    @patch("saq.modules.file_analysis.dotnet.is_dotnet")
    def test_execute_analysis_successful(self, mock_is_dotnet, mock_popen, ilspy_config, root_analysis, tmpdir):
        mock_is_dotnet.return_value = True

        # mock the ilspy process
        mock_process = Mock()
        mock_process.communicate.return_value = (None, b"")
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        analyzer = IlspyAnalyzer(context=create_test_context(root=root_analysis))

        test_file = tmpdir / "test.exe"
        test_file.write("fake dotnet content")

        file_observable = root_analysis.add_file_observable(str(test_file))

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should have created analysis
        analysis = file_observable.get_analysis(IlspyAnalysis)
        assert analysis is not None
        assert isinstance(analysis, IlspyAnalysis)

        # check analysis properties
        assert analysis.exit_code == 0
        assert analysis.stderr is None  # empty bytes b"" evaluates to None

        # check that il file was added as observable
        il_observable = None
        for obs in analysis.observables:
            if isinstance(obs, FileObservable) and obs.file_name.endswith(".il"):
                il_observable = obs
                break

        assert il_observable is not None
        assert il_observable.has_relationship(R_EXTRACTED_FROM)
        assert il_observable.redirection == file_observable

    @patch("saq.modules.file_analysis.dotnet.Popen")
    @patch("saq.modules.file_analysis.dotnet.is_dotnet")
    def test_execute_analysis_with_stderr(self, mock_is_dotnet, mock_popen, ilspy_config, root_analysis, tmpdir):
        mock_is_dotnet.return_value = True

        # mock the ilspy process with stderr
        mock_process = Mock()
        mock_process.communicate.return_value = (None, b"warning message")
        mock_process.returncode = 1
        mock_popen.return_value = mock_process

        analyzer = IlspyAnalyzer(context=create_test_context(root=root_analysis))

        test_file = tmpdir / "test.exe"
        test_file.write("fake dotnet content")

        file_observable = root_analysis.add_file_observable(str(test_file))

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should have created analysis
        analysis = file_observable.get_analysis(IlspyAnalysis)
        assert analysis is not None
        assert analysis.exit_code == 1
        assert analysis.stderr == "warning message"

    @patch("saq.modules.file_analysis.dotnet.Popen")
    @patch("saq.modules.file_analysis.dotnet.is_dotnet")
    def test_execute_analysis_timeout(self, mock_is_dotnet, mock_popen, ilspy_config, root_analysis, tmpdir):
        mock_is_dotnet.return_value = True

        # mock the ilspy process to timeout on first communicate, then return on second
        mock_process = Mock()
        mock_process.communicate.side_effect = [
            TimeoutExpired(cmd="ilspy", timeout=10),
            (None, b"")
        ]
        mock_process.kill = Mock()
        mock_popen.return_value = mock_process

        analyzer = IlspyAnalyzer(context=create_test_context(root=root_analysis))

        test_file = tmpdir / "test.exe"
        test_file.write("fake dotnet content")

        file_observable = root_analysis.add_file_observable(str(test_file))

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # verify kill was called
        mock_process.kill.assert_called_once()

        # should have created analysis
        analysis = file_observable.get_analysis(IlspyAnalysis)
        assert analysis is not None

    @patch("saq.modules.file_analysis.dotnet.Popen")
    @patch("saq.modules.file_analysis.dotnet.is_dotnet")
    def test_execute_analysis_exception(self, mock_is_dotnet, mock_popen, ilspy_config, root_analysis, tmpdir):
        mock_is_dotnet.return_value = True

        # mock the ilspy process to raise an exception
        mock_popen.side_effect = Exception("Test exception")

        analyzer = IlspyAnalyzer(context=create_test_context(root=root_analysis))

        test_file = tmpdir / "test.exe"
        test_file.write("fake dotnet content")

        file_observable = root_analysis.add_file_observable(str(test_file))

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should have created analysis with error in stderr
        analysis = file_observable.get_analysis(IlspyAnalysis)
        assert analysis is not None
        assert analysis.stderr == "Test exception"

    @patch("saq.modules.file_analysis.dotnet.Popen")
    @patch("saq.modules.file_analysis.dotnet.is_dotnet")
    def test_execute_analysis_duplicate_filename(self, mock_is_dotnet, mock_popen, ilspy_config, root_analysis, tmpdir):
        mock_is_dotnet.return_value = True

        # mock the ilspy process
        mock_process = Mock()
        mock_process.communicate.return_value = (None, b"")
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        analyzer = IlspyAnalyzer(context=create_test_context(root=root_analysis))

        test_file = tmpdir / "test.exe"
        test_file.write("fake dotnet content")

        file_observable = root_analysis.add_file_observable(str(test_file))

        # create the target file that would normally be created by ilspy
        # this simulates a duplicate filename scenario
        target_path = root_analysis.create_file_path(f"{file_observable.file_name}_ilspy.il")
        with open(target_path, "w") as f:
            f.write("existing content")

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should have created analysis
        analysis = file_observable.get_analysis(IlspyAnalysis)
        assert analysis is not None

        # check that a new il file with index was created
        il_observable = None
        for obs in analysis.observables:
            if isinstance(obs, FileObservable) and obs.file_name.endswith(".il"):
                il_observable = obs
                break

        assert il_observable is not None
        # should have _0 in the name due to duplicate
        assert "_ilspy_0.il" in il_observable.file_name

    @patch("saq.modules.file_analysis.dotnet.Popen")
    @patch("saq.modules.file_analysis.dotnet.is_dotnet")
    def test_execute_analysis_max_duplicates(self, mock_is_dotnet, mock_popen, ilspy_config, root_analysis, tmpdir):
        mock_is_dotnet.return_value = True

        analyzer = IlspyAnalyzer(context=create_test_context(root=root_analysis))

        test_file = tmpdir / "test.exe"
        test_file.write("fake dotnet content")

        file_observable = root_analysis.add_file_observable(str(test_file))

        # create target file and all duplicates up to the limit
        target_path = root_analysis.create_file_path(f"{file_observable.file_name}_ilspy.il")
        with open(target_path, "w") as f:
            f.write("existing content")

        # create all duplicate files
        for i in range(1024):
            target_path = root_analysis.create_file_path(f"{file_observable.file_name}_ilspy_{i}.il")
            with open(target_path, "w") as f:
                f.write("existing content")

        result = analyzer.execute_analysis(file_observable)
        assert result == AnalysisExecutionResult.COMPLETED

        # should not have created analysis because no valid path was available
        analysis = file_observable.get_analysis(IlspyAnalysis)
        assert analysis is None
