#!/bin/bash


#####################################################
#
#	       usercreation_script.sh
#
#   Fast user creation script for onboarding 
#
#####################################################

# ask for username, prompt for password 
# create a folder for new employee
echo "Enter in employee intial followed by last name."
read username

sudo useradd -m -s /bin/bash $username

sudo passwd $username

sudo mkdir /home/$username/Welcome_Docs
sudo chown $username:$username /home/$username/Welcom_Docs

echo "Welcome to the team $username!"
