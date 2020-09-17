# -*- coding: utf-8 -*-
from __future__ import unicode_literals

INSTANCE_FORMAT_TYPE_XML = "xml"
INSTANCE_FORMAT_TYPE_JSON = "json"

ASSET_TYPE_TEXT = 'text'
ASSET_TYPE_EMPTY = 'empty'
ASSET_TYPE_QUESTION = 'question'
ASSET_TYPE_BLOCK = 'block'
ASSET_TYPE_SURVEY = 'survey'
ASSET_TYPE_TEMPLATE = 'template'

ASSET_TYPES = [
    (ASSET_TYPE_TEXT, ASSET_TYPE_TEXT),               # uncategorized, misc
    (ASSET_TYPE_EMPTY, ASSET_TYPE_EMPTY),             # useless, probably should be pruned

    (ASSET_TYPE_QUESTION, ASSET_TYPE_QUESTION),       # has no name
    (ASSET_TYPE_BLOCK, ASSET_TYPE_BLOCK),             # has a name, but no settings
    (ASSET_TYPE_SURVEY, ASSET_TYPE_SURVEY),           # has name, settings
    (ASSET_TYPE_TEMPLATE, ASSET_TYPE_TEMPLATE),       # quite same as survey, but can't be deployed, no submissions
]


CLONE_ARG_NAME = "clone_from"
CLONE_FROM_VERSION_ID_ARG_NAME = "clone_from_version_id"
COLLECTION_CLONE_FIELDS = {"name"}

# Types are declared in `kpi.models.assets.ASSET_TYPES`.
# These values correspond to index 0 of each tuple of ASSET_TYPES
CLONE_COMPATIBLE_TYPES = {
    ASSET_TYPE_TEXT: [ASSET_TYPE_TEXT],  # We don't know if it's used, so keep it safe, only allow cloning from/to its own kind
    ASSET_TYPE_EMPTY: [ASSET_TYPE_EMPTY],  # We don't know if it's used, so keep it safe, only allow cloning from/to its own kind
    ASSET_TYPE_QUESTION: [ASSET_TYPE_QUESTION, ASSET_TYPE_SURVEY, ASSET_TYPE_TEMPLATE],
    ASSET_TYPE_BLOCK: [ASSET_TYPE_BLOCK, ASSET_TYPE_QUESTION, ASSET_TYPE_SURVEY, ASSET_TYPE_TEMPLATE],
    ASSET_TYPE_SURVEY: [ASSET_TYPE_BLOCK, ASSET_TYPE_QUESTION, ASSET_TYPE_SURVEY, ASSET_TYPE_TEMPLATE],
    ASSET_TYPE_TEMPLATE: [ASSET_TYPE_SURVEY, ASSET_TYPE_TEMPLATE]
}

ASSET_TYPE_ARG_NAME = "asset_type"

SHADOW_MODEL_APP_LABEL = "shadow_model"

# List of nested attributes which bypass 'dots' encoding
NESTED_MONGO_RESERVED_ATTRIBUTES = [
    "_validation_status",
]

# ASSIGNABLE_PERMISSIONS
PERM_VIEW_ASSET = 'view_asset'
PERM_CHANGE_ASSET = 'change_asset'
PERM_ADD_SUBMISSIONS = 'add_submissions'
PERM_VIEW_SUBMISSIONS = 'view_submissions'
PERM_SUPERVISOR_VIEW_SUBMISSION = 'supervisor_view_submissions'
PERM_CHANGE_SUBMISSIONS = 'change_submissions'
PERM_VALIDATE_SUBMISSIONS = 'validate_submissions'


# CALCULATED_PERMISSIONS
PERM_SHARE_ASSET = 'share_asset'
PERM_DELETE_ASSET = 'delete_asset'
PERM_SHARE_SUBMISSIONS = 'share_submissions'
PERM_DELETE_SUBMISSIONS = 'delete_submissions'

# MAPPED_PARENT_PERMISSIONS
PERM_VIEW_COLLECTION = 'view_collection'
PERM_CHANGE_COLLECTION = 'change_collection'

# KC INTERNAL
PERM_FROM_KC_ONLY = 'from_kc_only'

