# Release 0.9

## Features
* Kernel Acquisition for OSX (Process tracking + FileIo tracking)
* Services tracking.
* Drivers tracking.
* Autoruns tracking.
* File access notification (Windows).

## Notes
* This release is not backwards compatible with the previous HCP as some centralized rpal functions were added to better support kernel acquisition.
* The new kernel acquisition framework is implemented only on OSX for now due to OSX's very limiting new rootless mode. More platforms likely to come. The kernel acquisition is an HCP module that can be loaded in parallel to HBS. If present, HBS will transparently switch to using it for certain capabilities (like process tracking). Many more capabilities will be added in the kernel, especially on OSX.