// Login.jsx

import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Formik, Form, Field, ErrorMessage } from "formik";
import * as Yup from "yup";
import "./login.css";
import { toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';


const LoginSchema = Yup.object().shape({
  username: Yup.string().required("Username is required"),
  password: Yup.string().required("Password is required"),
});

const Login = () => {
  const history = useNavigate();
  const [loginError, setLoginError] = useState("");

  const handleLogin = async (values, { setSubmitting }) => {
    try {
      const { username, password } = values;
      // Send POST request to the server for authentication
      const response = await fetch("http://localhost:5555/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          
          
        },
        credentials: "include",
 
        body: JSON.stringify({ username, password }),
      });
      if (response.ok) {
        // Redirect to homepage after successful login
        
        response.json()
        .then(data => {
            console.log(data.message)
            history("/")
            toast.success('Welcome Back!!', {
              position: 'top-right',
              autoClose: 3000,
            });
        })
      } else {
        // Handle failed login
        setLoginError("Invalid username or password.");
      }
    } catch (error) {
      console.error("Error:", error);
      setLoginError("An error occurred. Please try again later.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="login-signup">
      <div className="login-form">
        <h1>Login</h1>
        <Formik
          initialValues={{ username: "", password: "" }}
          validationSchema={LoginSchema}
          onSubmit={handleLogin}
        >
          {({ isSubmitting, errors }) => (
            <Form>
              <div className="input-field">
                <label htmlFor="username" className="label">
                  Username
                </label>
                <Field
                  type="text"
                  name="username"
                  id="username"
                  className={`input ${errors.username ? "field-error" : ""}`}
                />
                <ErrorMessage
                  name="username"
                  component="div"
                  className="error-message"
                />
              </div>
              <div className="input-field">
                <label htmlFor="password" className="label">
                  Password
                </label>
                <Field
                  type="password"
                  name="password"
                  id="password"
                  className={`input ${errors.password ? "field-error" : ""}`}
                />
                <ErrorMessage
                  name="password"
                  component="div"
                  className="error-message"
                />
              </div>
              {loginError && <div>{loginError}</div>}
              <button type="submit" className="btn btn-primary" disabled={isSubmitting}>
                Login
              </button>
            </Form>
          )}
        </Formik>
        <p>
          Don't have an account?{" "}
          <Link to="/signup" className="login-link">
            Signup
          </Link>
        </p>
        <p>
          <Link to="/forgot-password" className="login-link">
            Forgot password?
          </Link>
        </p>
      </div>
    </div>
  );
};

export default Login;