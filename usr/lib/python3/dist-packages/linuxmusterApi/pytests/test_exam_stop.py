import pytest

from routers_v1.body_schemas import StopExam
from routers_v1.exam import stop_exam_mode
from security import AuthenticatedUser

WHO = AuthenticatedUser(dn='', user='ga', role='globaladministrator', school='global')


class FakeProcess:
    """Stands in for the sophomorix-exam-mode process: records argv, answers with a JSON block on stderr."""

    def __init__(self, cmd, calls):
        calls.append(cmd)

    def communicate(self):
        return b'', b"# JSON-begin\n{'COMMENT_EN': 'ok'}\n# JSON-end\n"


@pytest.fixture
def calls(monkeypatch):
    recorded = []
    monkeypatch.setattr('utils.sophomorix.subprocess.Popen', lambda cmd, **kwargs: FakeProcess(cmd, recorded))
    return recorded


def subdir(cmd):
    return cmd[cmd.index('--subdir') + 1]


class TestStopExamTarget:

    def test_without_group_the_name_has_no_none(self, calls):
        result = stop_exam_mode(StopExam(users=['s01']), None, None, background=False, who=WHO)

        assert 'None' not in result['target']
        assert result['target'].startswith('EXAM_')
        assert subdir(calls[0]) == f"transfer/collected/{result['target']}"

    def test_with_group_the_name_carries_type_and_name(self, calls):
        result = stop_exam_mode(StopExam(users=['s01'], group_type='classes', group_name='8a'), None, None, background=False, who=WHO)

        assert result['target'].startswith('EXAM_classes_8a_')

    def test_a_returned_target_collects_the_next_batch_in_the_same_directory(self, calls):
        first = stop_exam_mode(StopExam(users=['s01', 's02'], group_type='classes', group_name='8a'), None, None, background=False, who=WHO)
        stop_exam_mode(StopExam(users=['s03'], group_type='classes', group_name='8a', target=first['target']), None, None, background=False, who=WHO)

        assert subdir(calls[0]) == subdir(calls[1])

    def test_a_target_sent_by_the_client_is_escaped(self, calls):
        result = stop_exam_mode(StopExam(users=['s01'], target="../x'; rm -rf"), None, None, background=False, who=WHO)

        assert result['target'] == '___x___rm_-rf'
        assert subdir(calls[0]) == 'transfer/collected/___x___rm_-rf'
