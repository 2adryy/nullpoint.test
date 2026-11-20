"""Start the SecureChat web client:  python client.py

Opens the chat page in your browser at http://127.0.0.1:8080/ (next free port if busy).
All encryption runs here in Python; the browser is only the user interface.
"""

from securechat.web_client import main

if __name__ == "__main__":
    main()
