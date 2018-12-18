public function Generate()
    Dim myFilePath
    Set myShell = CreateObject("Wscript.shell")
    Set myFileSystemObj = CreateObject("Scripting.FileSystemObject")
    myFilePath = myShell.ExpandEnvironmentStrings("%allusersprofile%") + "\.keytalk_uuid"

    If (myFileSystemObj.FileExists(myFilePath)) Then
        exit function
    End If

    Set myWriteObj = myFileSystemObj.OpenTextFile(myFilePath, 2, true)

    Set TypeLib = CreateObject("Scriptlet.TypeLib")
    Dim myGuidVal
    ' Assuming Guid is generated in the following style: {00000000-0000-0000-0000-000000000000}
    myGuidVal = LCase(Left(TypeLib.Guid, 38))
    ' Remove UUID stylized elements: brackets and dashes
    myGuidVal = Replace(myGuidVal,"-","")
    myGuidVal = Replace(myGuidVal,"}","")
    myGuidVal = Replace(myGuidVal,"{","")
    myWriteObj.WriteLine(myGuidVal)

    Set myWriteObj = Nothing
    exit function
end function
