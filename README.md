# Usage

Run on the command line with the necessary parameters

example:
```python
python3 cbcBitFlipping.py \
--url "http://127.0.0.1:9091/read" \
--session "76xobRieNsQtbEbN8RFt6lyzY5qChDQWRW4meH3WrL/ELv5GBB7vktl5Kb+NEkMeBK7EXXruHJvjT70mDFJWig==" \
--old '{"admin": 0, "username": "user1"}' \
--new '{"admin": 1, "username": "user1"}' \
--param filename test.txt \
--delay 0.1 \
--success-substring "File not found."
```


Enter the original session content at the --old parameter and the desired tampered session content at the --new parameter.

If necessary, enter the parameters and values you want to attach to the -param parameter.

Type the keyword included in the returned packet after successfully bypassing forensics at success-substring to make it easier for the script to identify which rollover attack was successful.


# Acknowledgments

My Computer
