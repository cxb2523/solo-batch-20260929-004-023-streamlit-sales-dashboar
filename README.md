
# Add a User Authentication Service (Login Form) in Streamlit

In this video, I will show you how to add a user authentication service (login form) in Streamlit so that your users can log in and see the content of your streamlit app. To implement the user authentication, we will use the ‘streamlit-authenticator’ library, a secure authentication module to validate user credentials in a Streamlit application.

## Video Tutorial
[![YouTube Video](https://img.youtube.com/vi/JoFGrSRj4X4/0.jpg)](https://youtu.be/JoFGrSRj4X4)

## Credentials

All credential handling lives in `credentials.py`; both the login route in
`app.py` and the generator use it, and paths are anchored to the project root
(the launch working directory is irrelevant).

- Generate the current file: `python generate_keys.py` -> `credentials.yaml`
  (bcrypt hashes via `streamlit_authenticator.Hasher`, written atomically;
  password changes are picked up without restarting the app).
- Default logins: `pparker` / `abc123`, `rmiller` / `def456`.
- The old flat `hashed_pw.pkl` still works when `credentials.yaml` is absent;
  the login page shows a migration banner until the YAML file is created.
- A present but unrecognisable file raises a `MigrationError`; the reason is
  shown on the login page instead of falling back to empty/legacy credentials.
- Verify everything with `python verify_auth.py`.

## Demo Website
⭐ https://userauth-dashboard.herokuapp.com/

## Screenshot
![Login Screenshot](/demo.jpg?raw=true "Login Form")

## Streamlit-authenticator
⭐ Check out the library here: https://github.com/mkhorasani/Streamlit-Authenticator

## Learn Excel Automation with Python
If this repo helped you, my [Excel Automation Course](https://pythonandvba.com/excel-automation-course/) teaches the full workflow from zero: Python for Excel users, xlwings, pandas and real projects.

Also check out my other [tools and templates](https://pythonandvba.com/solutions).

## Connect with Me
- **YouTube:** [CodingIsFun](https://youtube.com/c/CodingIsFun)
- **Website:** [PythonAndVBA](https://pythonandvba.com)
- **LinkedIn:** [Sven Bosau](https://www.linkedin.com/in/sven-bosau/)
- **Contact:** [Get in Touch](https://pythonandvba.com/contact)
## Support
If you find this project helpful, consider buying me a coffee. 

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://pythonandvba.com/coffee-donation)
