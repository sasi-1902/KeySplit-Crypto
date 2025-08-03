from user_module import register_user, authenticate_user

register_user('TestUser', 'test123', 'SecurePass123!')
print('User created. Auth test:', authenticate_user('test123', 'SecurePass123!'))
