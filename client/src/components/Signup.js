// Signup.jsx

import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Formik, Form, Field, ErrorMessage } from "formik";
import * as Yup from "yup";
import "./signup.css";
import {toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

const SignupSchema = Yup.object().shape({
  username: Yup.string().required("Username is required"),
  email: Yup.string().email("Invalid email").required("Email is required"),
  password: Yup.string().required("Password is required"),
});

const Signup = () => {
  const history = useNavigate();
  const [signupError, setSignupError] = useState("");

  const handleSignup = async (values, { setSubmitting }) => {
    try {
      const { username, email, password } = values;
      const response = await fetch("http://127.0.0.1:5555/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
  
        },
        body: JSON.stringify({ username, email, password }),
      });
      
      if (response.ok) {
        // Redirect to login page after successful signup
        history("/login");
        response.json()
        .then(data => {
            console.log(data.message)
            toast.success('You are registered please login', {
              position: 'top-right',
              autoClose: 6000,
            });
        })
      } else {
        // Handle failed signup
        setSignupError(data.message || "Failed to signup. Please try again.");
      }
    } catch (error) {
      console.error("Error:", error);
      setSignupError("An error occurred. Please try again later.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="login-signup">
      <div className="signup-form">
        <h1>Signup</h1>
        <Formik
          initialValues={{ username: "", email: "", password: "" }}
          validationSchema={SignupSchema}
          onSubmit={handleSignup}
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
                <label htmlFor="email" className="label">
                  Email
                </label>
                <Field
                  type="email"
                  name="email"
                  id="email"
                  className={`input ${errors.email ? "field-error" : ""}`}
                />
                <ErrorMessage
                  name="email"
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
              {signupError && <div>{signupError}</div>}
              <button
                type="submit"
                className="btn btn-primary"
                disabled={isSubmitting}
              >
                Submit
              </button>
            </Form>
          )}
        </Formik>
        <p>
          Already have an account?{" "}
          <Link to="/login" className="login-link">
            Login
          </Link>
        </p>
      </div>
    </div>
  );
};

export default Signup;