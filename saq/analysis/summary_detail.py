from uuid import uuid4

ID = 'id'
HEADER = 'header'
CONTENT = 'content'
FORMAT = 'format'

class SummaryDetail:
    """Represents a summary detail to present to the analyst.

    Details added to Analysis objects are displayed inline with the analysis
    tree. Details added to RootAnalysis are displayed at the top of the
    display."""


    def __init__(self, header=None, content=None, format=None, id=None):
        # generic uuid
        self.id = str(uuid4()) if id is None else id
        # the visual header displayed above the summary
        self.header = header
        # the actual content of the summary
        self.content = content
        # the format of the content (see saq/constants.py for SUMMARY_DETAIL_FORMAT_* values)
        self.format = format

    def to_dict(self):
        return {
            ID: self.id,
            HEADER: self.header,
            CONTENT: self.content,
            FORMAT: self.format,
        }

    @staticmethod
    def from_dict(d):
        result = SummaryDetail()
        if ID in d:
            result.id = d[ID]
        if HEADER in d:
            result.header = d[HEADER]
        if CONTENT in d:
            result.content = d[CONTENT]
        if FORMAT in d:
            result.format = d[FORMAT]
        return result

    @property
    def json(self):
        return self.to_dict()

    def __eq__(self, other):
        if not isinstance(other, SummaryDetail):
            return False

        return self.id == other.id