# Merging oauth multiple accounts
The prototype app implemented in Python and  Flask. It provides functionality to merge user multiple accounts, while they chose different way to log in.

# App details

The application is based on the provided below database design:

<center>
<img src="http://www.vertabelo.com/_file/github/merging-multiple-oauth-accounts/database_design.png"/>
</center

The prototype app will enable user:

1. Create an account in the app.

<img src="http://www.vertabelo.com/_file/github/merging-multiple-oauth-accounts/sign_up_form.png"/>

2. Log in via a created account or other services (Facebook, Google, LinkedIn, Github).

<img src="http://www.vertabelo.com/_file/github/merging-multiple-oauth-accounts/log_in_screen.png"/>

3. Add some content that is associated with this account. In this case, it is a list of todo items.

<img src="http://www.vertabelo.com/_file/github/merging-multiple-oauth-accounts/create_new_todo_screen.png"/>

4. Connect other social media accounts. When logged in, the user can manually add other social accounts to their profile. Once these accounts are added, the same user account will be loaded no matter which login is used.

<img src="http://www.vertabelo.com/_file/github/merging-multiple-oauth-accounts/my_logins_facebook_account_connected.png"/>

# Installation

Download bootstrap and jquery via bower:

`bower install` 

To run the application type:

`python app.py` 


