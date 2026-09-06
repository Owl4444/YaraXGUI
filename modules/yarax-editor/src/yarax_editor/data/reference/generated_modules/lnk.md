# lnk — YARA-X 1.20.0

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

Generated from the official protobuf definitions and Rust exports. Availability depends on the engine build and field feature restrictions.

## lnk.Lnk

### is_lnk

Type: bool

True if the file is a LNK file.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### name

Type: string

A description of the shortcut that is displayed to end users to identify
 the purpose of the link.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### creation_time

Type: uint64

Time when the LNK file was created.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### access_time

Type: uint64

Time when the LNK file was last accessed.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### write_time

Type: uint64

Time when the LNK files was last modified.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### file_size

Type: uint32

Size of the target file in bytes. The target file is the file that this
 link references to. If the link target file is larger than 0xFFFFFFFF,
 this value specifies the least significant 32 bits of the link target file
 size.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### file_attributes

Type: uint32

Attributes of the link target file.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### icon_location

Type: string

Location where the icon associated to the link is found. This is usually
 an EXE or DLL file that contains the icon among its resources. The
 specific icon to be used is indicated by the `icon_index` field.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### icon_index

Type: uint32

Index of the icon that is associated to the link, within an icon location.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### show_command

Type: lnk.ShowCommand

Expected window state of an application launched by this link.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### drive_type

Type: lnk.DriveType

Type of drive the link is stored on.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### drive_serial_number

Type: uint32

Drive serial number of the volume the link target is stored on.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### volume_label

Type: string

Volume label of the drive the link target is stored on.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### local_base_path

Type: string

String used to construct the full path to the link target by appending the
 common_path_suffix field.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### common_path_suffix

Type: string

String used to construct the full path to the link target by being appended
 to the local_base_path field.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### relative_path

Type: string

Location of the link target relative to the LNK file.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### working_dir

Type: string

Path of the working directory to be used when activating the link target.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### cmd_line_args

Type: string

Command-line arguments that are specified when activating the link target.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### overlay_size

Type: uint64

Size in bytes of any extra data appended to the LNK file.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### overlay_offset

Type: uint64

Offset within the LNK file where the overlay starts.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### tracker_data

Type: lnk.TrackerData

Distributed link tracker information.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### target_id_list

Type: array of lnk.ShellItem

Shell items parsed from the link target ID list (LINKTARGET_IDLIST). This
 list describes the target of the shortcut as a chain of shell items (root
 folder, volume, file entry, control panel item, etc.).

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### DriveType

Type: lnk.Lnk.@DriveType

Constant namespace

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### FILE_ATTRIBUTE_READONLY

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### FILE_ATTRIBUTE_HIDDEN

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### FILE_ATTRIBUTE_SYSTEM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### RESERVED_1

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### FILE_ATTRIBUTE_DIRECTORY

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### FILE_ATTRIBUTE_ARCHIVE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### RESERVED_2

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### FILE_ATTRIBUTE_NORMAL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### FILE_ATTRIBUTE_TEMPORARY

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### FILE_ATTRIBUTE_SPARSE_FILE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### FILE_ATTRIBUTE_REPARSE_POINT

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### FILE_ATTRIBUTE_COMPRESSED

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### FILE_ATTRIBUTE_OFFLINE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### FILE_ATTRIBUTE_NOT_CONTENT_INDEXED

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### FILE_ATTRIBUTE_ENCRYPTED

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### ShellItemType

Type: lnk.Lnk.@ShellItemType

Constant namespace

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### ShowCommand

Type: lnk.Lnk.@ShowCommand

Constant namespace

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

## lnk.ShowCommand

### NORMAL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### MAXIMIZED

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### MIN_NO_ACTIVE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

## lnk.DriveType

### UNKNOWN

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### NO_ROOT_DIR

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### REMOVABLE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### FIXED

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### REMOTE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### CDROM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### RAMDISK

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

## lnk.TrackerData

### version

Type: uint32

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### machine_id

Type: string

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### droid_volume_id

Type: string

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### droid_file_id

Type: string

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### droid_birth_volume_id

Type: string

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### droid_birth_file_id

Type: string

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

## lnk.ShellItem

### item_type

Type: lnk.ShellItemType

Type (category) of the shell item, derived from the class type indicator
 byte. Always set for every shell item: when the class type indicator
 maps to a known category, the corresponding enum variant is used;
 otherwise, the raw class type indicator byte is stored as an unknown value.

Field annotations:
```json
{
  "fmt": "x"
}
```

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### data

Type: bytes

The raw class type specific data of the shell item: all the bytes that
 follow the class type indicator byte. Always populated, which allows rules
 to match on shell items whose type is not decoded into a dedicated field
 below.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### cpl_file_path

Type: string

Path to the control panel CPL file. Populated for control panel CPL file
 shell items (item_type CONTROL_PANEL_CPL).

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### root_folder_id

Type: string

Shell folder identifier (a GUID). Populated for root folder shell items
 (item_type ROOT_FOLDER).

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### volume_name

Type: string

Volume name. Populated for volume shell items (item_type VOLUME) that
 carry a name.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### volume_id

Type: string

Volume identifier (a GUID). Populated for volume shell items
 (item_type VOLUME) that carry an identifier instead of a name.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### file_entry_name

Type: string

File or directory name. Populated for file entry shell items
 (item_type FILE_ENTRY).

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### network_location

Type: string

Network location (usually a UNC path). Populated for network location
 shell items (item_type NETWORK_LOCATION).

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

## lnk.ShellItemType

### CONTROL_PANEL_CPL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### CONTROL_PANEL_CATEGORY

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### ROOT_FOLDER

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### VOLUME

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### FILE_ENTRY

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### NETWORK_LOCATION

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### COMPRESSED_FOLDER

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### URI

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### CONTROL_PANEL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### PRINTERS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### COMMON_PLACES_FOLDER

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### USERS_FILES_FOLDER

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

## lnk.Lnk.@DriveType

### UNKNOWN

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### NO_ROOT_DIR

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### REMOVABLE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### FIXED

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### REMOTE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### CDROM

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### RAMDISK

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

## lnk.Lnk.@ShellItemType

### CONTROL_PANEL_CPL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### CONTROL_PANEL_CATEGORY

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### ROOT_FOLDER

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### VOLUME

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### FILE_ENTRY

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### NETWORK_LOCATION

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### COMPRESSED_FOLDER

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### URI

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### CONTROL_PANEL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### PRINTERS

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### COMMON_PLACES_FOLDER

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### USERS_FILES_FOLDER

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

## lnk.Lnk.@ShowCommand

### NORMAL

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### MAXIMIZED

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto

### MIN_NO_ACTIVE

Type: integer

No additional prose description in the upstream definition.

Source: https://github.com/VirusTotal/yara-x/blob/60ad06971467029e77967e59d580cbbe85a1474d/lib/src/modules/protos/lnk.proto
