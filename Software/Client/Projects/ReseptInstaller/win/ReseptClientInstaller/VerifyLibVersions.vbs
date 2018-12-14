' The script verifies versions of 3rd party libraries before including them in the MSI installer
'
' The reason for that is to prevent the situation when upgrading an existing KeyTalk client installation
' from the msi (inadvertently) holding older versions of (some of) these libs makes the installer to skip installing
' these libs from the new msi package after successful removal of the existing ones
'

' LIBRARY VERSIONS CAN EITHER STAY THE SAME OR GROW FOR NEW KEYTALK INSTALLERS.
' THEY SHOULD NEVER GO DOWN!
QtLibs = Array("Qt5Core.dll", "Qt5Gui.dll", "Qt5Widgets.dll", "platforms\qwindows.dll")
IcuLibs = Array("icudt54.dll", "icuin54.dll", "icuuc54.dll")
VcRuntimeLibs = Array("msvcr120.dll", "msvcp120.dll", "vccorlib120.dll")
ZlibLibs = Array("zlibwapi.dll")
Const ExpectedQtVersion = "5.5.1.0"
Const ExpectedIculibVersion = "54.1.0.0"
Const ExpecteVcRuntimeLibVersion = "12.0.21005.1"
Const ExpectedZlibVersion = "1.2.8.0"

Const LibDir="..\..\..\Export\"
Dim oFSO : Set oFSO = CreateObject("Scripting.FileSystemObject")

checkLibs QtLibs, ExpectedQtVersion
checkLibs IcuLibs, ExpectedIculibVersion
checkLibs VcRuntimeLibs, ExpecteVcRuntimeLibVersion
checkLibs ZlibLibs, ExpectedZlibVersion

Function checkLibs(libs, expected_version)
    For Each lib in libs
        WScript.StdOut.WriteLine "Checking " & lib
        path = LibDir & lib
        version = oFSO.GetFileVersion(path)
        If version <> expected_version Then
            WScript.StdOut.WriteLine "Invalid version of " & lib & ". Actual: " & version & ", expected: " & expected_version
            WScript.Quit 1
        End If
    Next
End Function
