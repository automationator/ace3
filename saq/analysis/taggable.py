import logging
from saq.analysis.tag import Tag

KEY_TAGS = 'tags'

class TagManager:
    """Manages tag-related functionality for any object through composition."""

    def __init__(self, tags: list[Tag]):
        self._tags = tags

    @property
    def tags(self) -> list[Tag]:
        return self._tags

    @tags.setter
    def tags(self, value: list[Tag]):
        assert isinstance(value, list)
        assert all([isinstance(i, str) or isinstance(i, Tag) for i in value])
        # we manage a reference to the list so we can't just set it to the new value
        self._tags.clear()
        self._tags.extend(value)

    #
    # XXX for some reason we work with strings but store Tag objects
    #

    def add_tag(self, tag: str):
        assert isinstance(tag, str)
        if tag in [t.name for t in self._tags]:
            return

        t = Tag(name=tag)
        self.tags.append(t)
        
    def remove_tag(self, tag: str):
        assert isinstance(tag, str)
        targets = [t for t in self.tags if t.name == tag]
        for target in targets:
            self.tags.remove(target)

    def clear_tags(self):
        self.tags.clear()

    def has_tag(self, tag_value):
        """Returns True if this object has this tag."""
        return tag_value in [x.name for x in self.tags]

    def get_json_data(self):
        """Returns tag data for JSON serialization."""
        return {KEY_TAGS: self.tags}

    def set_json_data(self, value):
        """Sets tag data from JSON deserialization."""
        if KEY_TAGS in value:
            self.tags = value[KEY_TAGS]

