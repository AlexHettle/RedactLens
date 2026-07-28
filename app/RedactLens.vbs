' One-click RedactLens launcher for Windows.
' Double-click this file: it starts the app under pythonw.exe (so no console
' window ever appears) and your browser opens to the UI. See launch.py for
' what actually happens; the server shuts itself down after the tab closes.
Option Explicit

Dim fso, shell, root, repo, py
Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

root = fso.GetParentFolderName(WScript.ScriptFullName)
repo = fso.GetParentFolderName(root)
py = repo & "\.venv\Scripts\pythonw.exe"

If Not fso.FileExists(py) Then
  MsgBox "Python virtual environment not found at ..\.venv\." & vbCrLf & vbCrLf & _
         "Run the dev-setup steps in README.md once, then double-click this again.", _
         vbExclamation, "RedactLens"
  WScript.Quit 1
End If

shell.CurrentDirectory = root
' 0 = hidden window, False = don't wait for it to finish.
shell.Run """" & py & """ """ & root & "\launch.py""", 0, False
