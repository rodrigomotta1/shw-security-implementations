# shw-security-implementations
Implementation of security functions for project Smart Health Wearable

## Important
1. The implementation of the security functions are located in the following path: `nRF5_SDK_17.0.2/nRF5_SDK_17.0.2_d674dde/personal`
2. The implementation of main function is on the following path: `shw-security-implementations/shw-security-implementations`
3. This project was programmed and tested to the following setup:
   1. nRF5 SDK version 17.0.2_d674dde
   2. Segger Embedded Studio version 5.10b
   3. C (gnu99 standard)
   4. C++ (gnu++98 standard)
   5. nRF52840 Eval Kit by Waveshare


## Setup
1. Clone this project
2. Donwload Segger Embedded Studio (version 5.10b)
3. Open project by double clicking .emProject file located at `shw-security-implementations/shw-security-implementations/pca10056/blank/ses`
4. In SES, go to Project > Options
5. At the left to search bar, change configurations to `Common`
6. Then, at the sidebar, select Build and then search for Project Macros.
7. At the prompted window, paste the following
```bash
SDK=/path-to-this-repo/nRF5_SDK_17.0.2/nRF5_SDK_17.0.2_d674dde
CMSIS_CONFIG_TOOL=$(SDK)/external_tools/cmsisconfig/CMSIS_Configuration_Wizard.jar
```
8. Finally, go back to the main window and try to build the project by pressing `Alt + Shift + F7`

In case it doesn't work, contact me.