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

public class ListenCommand implements BlabberCommand {
	private static final Logger logger = LogManager.getLogger("VeraDemo:ListenCommand");

	private Connection connect;

	private String username;

	public ListenCommand(Connection connect, String username) {
		super();
		this.connect = connect;
		this.username = username;
	}

	@Override
	public void execute(String blabberUsername) {
		String sqlQuery = "INSERT INTO listeners (blabber, listener, status) values (?, ?, 'Active');";
		logger.info(sqlQuery);
		PreparedStatement action;
		try {
			action = connect.prepareStatement(sqlQuery);

			action.setString(1, blabberUsername);
			action.setString(2, username);
			action.execute();

			// Use PreparedStatement for parameterized query to prevent SQL injection
			sqlQuery = "SELECT blab_name FROM users WHERE username = ?";
			try (PreparedStatement sqlStatement = connect.prepareStatement(sqlQuery)) {
				sqlStatement.setString(1, blabberUsername);
				// Sanitize for logging to prevent log injection
				try {
					logger.info("Query: SELECT blab_name FROM users WHERE username = " + URLEncoder.encode(blabberUsername, "UTF-8"));
				} catch (UnsupportedEncodingException e1) {
					logger.info("Query: SELECT blab_name FROM users WHERE username = [encoded]");
				}
				try (ResultSet result = sqlStatement.executeQuery()) {
					result.next();

					/* START EXAMPLE VULNERABILITY - NOW FIXED */
					String event = username + " started listening to " + blabberUsername + " (" + result.getString(1) + ")";
					sqlQuery = "INSERT INTO users_history (blabber, event) VALUES (?, ?)";
					try (PreparedStatement historyStatement = connect.prepareStatement(sqlQuery)) {
						historyStatement.setString(1, username);
						historyStatement.setString(2, event);
						// Sanitize for logging to prevent log injection
						try {
							logger.info("Query: INSERT INTO users_history (blabber, event) VALUES (" + URLEncoder.encode(username, "UTF-8") + ", " + URLEncoder.encode(event, "UTF-8") + ")");
						} catch (UnsupportedEncodingException e1) {
							logger.info("Query: INSERT INTO users_history (blabber, event) VALUES ([encoded], [encoded])");
						}
						historyStatement.execute();
					}
					/* END EXAMPLE VULNERABILITY - NOW FIXED */
				}
			}
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
