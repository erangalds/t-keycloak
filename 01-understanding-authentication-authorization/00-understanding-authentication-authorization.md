# 1. Understanding Authentication and Authorization

## What's the Difference? 🤔

Let's start with the basics, as these terms are often used interchangeably but have distinct meanings:

- **Authentication (AuthN)**: This is the process of **verifying who you are**. It's like presenting your ID to prove your identity.
    
    - _Example_: When you log in to a website with your username and password, you're authenticating yourself.
        
- **Authorization (AuthZ)**: This is the process of **determining what you are allowed to do** once your identity is confirmed. It's like being granted access to specific areas or actions based on your role or permissions.
    
    - _Example_: After logging in, you might be authorized to view your account balance but not to access administrative settings.

## Why Do We Need Them? 🤔

In today's interconnected world, applications often need to access resources or data from other services on behalf of a user without directly handling the user's credentials. This is where authentication and authorization frameworks become crucial:

+ **Security**: Prevents unauthorized access to sensitive data and functionalities
+ **Delegation**: Allows users to grant limited access to their resources to third-party applications without sharing their primary credentials.
+ **Scalability**: Centralizes identity management, making it easier to manage users and their permissions across multiple applications. 
+ **User Experience**: Provides a seamless login experience, often through Single-Sign-On (SSO).

> [!info]
> Here's a callout block.
> It supports **Markdown**, 
> 
> 



