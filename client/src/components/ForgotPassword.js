import React, { useState } from "react";
import { Formik, Form, Field, ErrorMessage } from "formik";
import * as Yup from "yup";
import "./forgotpassword.css";

const ForgotPasswordSchema = Yup.object().shape({
  email: Yup.string().email("Invalid email").required("Email is required"),
});

const ForgotPassword = () => {
  const [resetToken, setResetToken] = useState("");
  const [error, setError] = useState("");

  const handleForgotPassword = async (values, { setSubmitting }) => {
    try {
      const { email } = values;
      const response = await fetch("http://localhost:5555/forgot_password", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email }),
      });
      if (response.ok) {
        const data = await response.json();
        setResetToken(data.reset_token);
        setError("");
      } else {
        setError("Email not found");
      }
    } catch (error) {
      console.error("Error:", error);
      setError("An error occurred. Please try again later.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="forgot-password">
      <h1>Forgot Password</h1>
      <Formik
        initialValues={{ email: "" }}
        validationSchema={ForgotPasswordSchema}
        onSubmit={handleForgotPassword}
      >
        {({ isSubmitting, errors }) => (
          <Form>
            <div className="input-field">
              <label htmlFor="email">Email</label>
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
            {error && <div>{error}</div>}
            {resetToken && (
              <div>
                An email with reset instructions has been sent to{" "}
                <strong>{values.email}</strong>.
              </div>
            )}
            <button type="submit" disabled={isSubmitting}>
              Submit
            </button>
          </Form>
        )}
      </Formik>
    </div>
  );
};

export default ForgotPassword;