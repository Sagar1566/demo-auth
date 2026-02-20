# How to Test the AdaptiveAuth Framework

This document explains how to test the AdaptiveAuth framework to ensure it works correctly and provides value to developers.

## 1. Quick Start Test

To quickly verify the framework works:

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the main application
python main.py

# 3. Visit http://localhost:8000/docs to see the API documentation
```

## 2. Comprehensive Framework Tests

Run the automated test suite to validate all components:

```bash
python test_framework.py
```

This test suite validates:
- ✅ Framework imports work correctly
- ✅ Basic functionality (JWT tokens, etc.)
- ✅ Database operations
- ✅ API endpoint mounting
- ✅ Integration examples

## 3. Integration Test

Create a test application to verify integration:

```bash
python test_app.py
```

This creates a sample application demonstrating how to integrate the framework into your own projects.

## 4. Manual Testing

### API Endpoint Testing
1. Start the server: `python main.py`
2. Visit: `http://localhost:8000/docs`
3. Test the various authentication endpoints:
   - `/api/v1/auth/register` - User registration
   - `/api/v1/auth/login` - User login
   - `/api/v1/auth/adaptive-login` - Risk-based login
   - `/api/v1/auth/enable-2fa` - Enable two-factor authentication

### Integration Testing
1. Create a new Python file
2. Import and initialize the framework:
```python
from fastapi import FastAPI
from adaptiveauth import AdaptiveAuth

app = FastAPI()
auth = AdaptiveAuth(
    database_url="sqlite:///./test.db",
    secret_key="your-secret-key"
)

# Mount all routes
app.include_router(auth.router, prefix="/auth")
```

## 5. Verification Checklist

To ensure the framework provides value to developers:

- [ ] **Easy Installation**: Can be installed with `pip install -r requirements.txt`
- [ ] **Simple Integration**: Works with just a few lines of code
- [ ] **Comprehensive Features**: Provides JWT, 2FA, risk assessment, etc.
- [ ] **Good Documentation**: Clear README with usage examples
- [ ] **API Availability**: Endpoints work as documented
- [ ] **Error Handling**: Graceful handling of edge cases
- [ ] **Scalability**: Can handle multiple concurrent users
- [ ] **Security**: Implements proper security measures

## 6. Running Specific Tests

### Test Individual Components
```bash
# Test imports
python -c "from adaptiveauth import AdaptiveAuth; print('Import successful')"

# Test main app
python -c "import main; print('Main app loads successfully')"

# Test example app
python -c "import run_example; print('Example app loads successfully')"
```

## 7. Expected Outcomes

When properly tested, the AdaptiveAuth framework should:

1. **Be Developer-Friendly**: Easy to install and integrate
2. **Provide Security**: Robust authentication and authorization
3. **Offer Advanced Features**: 2FA, risk-based auth, etc.
4. **Scale Well**: Handle multiple users and requests
5. **Document Clearly**: Provide clear usage examples
6. **Handle Errors**: Manage failures gracefully

## 8. Troubleshooting

If tests fail:

1. Ensure all dependencies are installed: `pip install -r requirements.txt`
2. Check Python version compatibility (requires Python 3.9+)
3. Verify the database connection settings
4. Review the error messages for specific issues

## Conclusion

The AdaptiveAuth framework has been thoroughly tested and is ready for developers to use in their applications. It provides comprehensive authentication features while remaining easy to integrate and use.