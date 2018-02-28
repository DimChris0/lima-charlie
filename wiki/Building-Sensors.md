# Building Sensors

Building new sensors is more difficult than using the pre-built binaries. Unless you know what you're doing, need custom features (don't hesitate to suggest so it's implemented in the upstream LC) or need to support a new platform, we recommend you use the pre-built binaries.

## Windows
To be able to maintain easy backwards compatibility with mscrt, building on Windows will require Visual Studio
and version [3790.1830 of the DDK](https://drive.google.com/file/d/0By1gF-nvJEvVYkRmMHRNVm83T0k/view?usp=sharing).
- Install the DDK to %systemdrive%\winddk\3790.1830\
  - LC is currently built on Windows using Visual Studio 2013 with the Windows 2010 SP1 toolset (for compatibility).
  - You will also need Python installed.
  - The Windows Driver will also require WDK 8.1 and up to compile.
- Clone the Lima Charlie repository locally on your Windows box
- Run Visual Studio as Administrator (not 100% required but makes debugging easier since LC is designed to run as
admin)
- In Visual Studio, open the solution in `sensor/solutions/rpHCP.sln`
- When/if prompted, do NOT upgrade `.vcxproj` project files to a newer version as it may break things, new versions of Visual Studio can usually work fine with older project files
- You should be ready to build

## Nix
It's simpler, cd to the sensor/ directory and run `scons`. Build requirements may vary depending on the platform, for example building on OSX will require a standard installation of X-Code and Ubuntu will require the build-essentials package