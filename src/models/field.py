from enum import Enum


class ModelEnum(Enum):
    @classmethod
    def choices(cls):
        return [(e.value, e.name) for e in cls]

    @classmethod
    def values(cls):
        for x in cls:
            yield x.value
