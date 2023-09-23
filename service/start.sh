#!/bin/sh

gunicorn --bind [::]:5000 main:service
