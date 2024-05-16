import React, { useState } from "react";
import { Formik, Form, Field, ErrorMessage } from "formik";
import * as Yup from "yup";
import "./resetpassword.css";

const ResetPasswordSchema = Yup.object().shape({
  username: Yup.string().required("Username is required"),
  newPassword: Yup.string()
    .required("New Password is required")
    .min(8, "Password must be at least 8 characters"),
  confirmPassword: Yup.string()
    .oneOf([Yup.ref("newPassword"), null], "Passwords must match")
    .required("Confirm Password is required"),
});

const ResetPasswordForm = () => {
  const [resetToken, setResetToken] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = async (values, { setSubmitting }) => {
    try {
      const { username, newPassword } = values;
      const response = await fetch("http://localhost:5555/reset_password", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, newPassword }),
      });
      if (response.ok) {
        const data = await response.json();
        setResetToken(data.reset_token);
        setError("");
      } else {
        setError("Username not found");
      }
    } catch (error) {
      console.error("Error:", error);
      setError("An error occurred. Please try again later.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="reset-password">
      <h1>Reset Password</h1>
      <Formik
        initialValues={{ username: "", newPassword: "", confirmPassword: "" }}
        validationSchema={ResetPasswordSchema}
        onSubmit={handleSubmit}
      >
        {({ isSubmitting, errors }) => (
          <Form>
            {/* Username field */}
            <div className="input-field">
              <label htmlFor="username">Username</label>
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
            {/* New password field */}
            <div className="input-field">
              <label htmlFor="newPassword">New Password</label>
              <Field
                type="password"
                name="newPassword"
                id="newPassword"
                className={`input ${errors.newPassword ? "field-error" : ""}`}
              />
              <ErrorMessage
                name="newPassword"
                component="div"
                className="error-message"
              />
            </div>
            {/* Confirm password field */}
            <div className="input-field">
              <label htmlFor="confirmPassword">Confirm Password</label>
              <Field
                type="password"
                name="confirmPassword"
                id="confirmPassword"
                className={`input ${
                  errors.confirmPassword ? "field-error" : ""
                }`}
              />
              <ErrorMessage
                name="confirmPassword"
                component="div"
                className="error-message"
              />
            </div>
            {/* Error message */}
            {error && <div className="error">{error}</div>}
            {/* Success message */}
            {resetToken && (
              <div className="success">
                Your reset token: <strong>{resetToken}</strong>
              </div>
            )}
            {/* Submit button */}
            <button type="submit" disabled={isSubmitting}>
              Submit
            </button>
          </Form>
        )}
      </Formik>
    </div>
  );
};

export default ResetPasswordForm;