# blog_backend
    blog application using Google App Engine and python 2.7 

How to run the project

    *   required install google app engine , python 2.7 , Jinja
    *   in you terminal run this code google_appengine/dev_appserver.py ~/[path to blog_backend]
    *   open your browser http://localhost:8080/

Basic Blog

    By vistit /blog/  you will get all posts orderd by created date
    By click any post with open it in single page
    Can visit specific post by visit /blog/{blog_id}
    
 User Actions

    User can signup by visit /signup page and fill the registration form. 
    User can login by visit /login using same username and password.
    User can create new post by visit /blog/newpost
    User can edit only his posts by visit /blog/edit/{blog_id}
    User can delete only his posts by visit /blog/delete/{blog_id}
    User can like/unlike any post but not his own
    User can add comments 
