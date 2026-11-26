package com.veracode.verademo.commands;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

public class IgnoreCommand implements BlabberCommand {
	private static final Logger logger = LogManager.getLogger("VeraDemo:IgnoreCommand");

	private Connection connect;

	private String username;

	public IgnoreCommand(Connection connect, String username) {
		super();
		this.connect = connect;
		this.username = username;
	}

	@Override
	public void execute(String blabberUsername) {
		String sqlQuery = "DELETE FROM listeners WHERE blabber=? AND listener=?;";
		logger.info(sqlQuery);
		PreparedStatement action;
		try {
			action = connect.prepareStatement(sqlQuery);

			action.setString(1, blabberUsername);
			action.setString(2, username);
			action.execute();

			// Fix CWE-89: Use PreparedStatement with parameterized query
			sqlQuery = "SELECT blab_name FROM users WHERE username = ?";
			try (PreparedStatement sqlStatement = connect.prepareStatement(sqlQuery)) {
				sqlStatement.setString(1, blabberUsername);
				// Fix CWE-117: Sanitize user input before logging
				try {
					logger.info("Query: " + sqlQuery + " with username: " + URLEncoder.encode(blabberUsername, "UTF-8"));
				} catch (UnsupportedEncodingException e) {
					logger.info("Query: " + sqlQuery);
				}
				// Fix CWE-404: Use try-with-resources for ResultSet
				try (ResultSet result = sqlStatement.executeQuery()) {
					result.next();

					/* START EXAMPLE VULNERABILITY */
					String event = username + " is now ignoring " + blabberUsername + " (" + result.getString(1) + ")";
					// Fix CWE-89: Use PreparedStatement with parameterized query
					sqlQuery = "INSERT INTO users_history (blabber, event) VALUES (?, ?)";
					try (PreparedStatement insertStatement = connect.prepareStatement(sqlQuery)) {
						insertStatement.setString(1, username);
						insertStatement.setString(2, event);
						// Fix CWE-117: Sanitize user input before logging
						try {
							logger.info("Query: " + sqlQuery + " with blabber: " + URLEncoder.encode(username, "UTF-8") + " and event: " + URLEncoder.encode(event, "UTF-8"));
						} catch (UnsupportedEncodingException e) {
							logger.info("Query: " + sqlQuery);
						}
						insertStatement.execute();
					}
					/* END EXAMPLE VULNERABILITY */
				}
			}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
