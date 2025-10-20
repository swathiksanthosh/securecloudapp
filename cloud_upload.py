from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
import os

def upload_to_drive(file_path):
    gauth = GoogleAuth()
    gauth.LocalWebserverAuth()  # Opens a browser for login once
    drive = GoogleDrive(gauth)

    file_name = os.path.basename(file_path)
    gfile = drive.CreateFile({'title': file_name})
    gfile.SetContentFile(file_path)
    gfile.Upload()
    gfile.InsertPermission({
        'type': 'anyone',
        'value': 'anyone',
        'role': 'reader'
    })
    print("Uploaded:", file_name)
    print("File link:", gfile['alternateLink'])
    return gfile['alternateLink']
