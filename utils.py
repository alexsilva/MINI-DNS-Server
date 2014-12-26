import os

__author__ = 'alex'


def versioned_filepath(filepath, version=0):
    """ Creates a versioned release the filepath. Remove old versions of files"""
    filepath, ext = os.path.splitext(filepath)

    new_version = version + 1
    old_version = new_version - 1

    old_filepath = filepath + str(old_version if old_version > 0 else '') + ext
    filepath = filepath + str(new_version) + ext

    print(filepath, old_filepath)

    if old_filepath != filepath and os.path.exists(old_filepath):
        os.remove(old_filepath)
    return filepath