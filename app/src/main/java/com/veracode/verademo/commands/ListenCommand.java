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

			// Use PreparedStatement to prevent SQL injection
			sqlQuery = "SELECT blab_name FROM users WHERE username = ?";
			try (PreparedStatement sqlStatement = connect.prepareStatement(sqlQuery)) {
				sqlStatement.setString(1, blabberUsername);
				// Sanitize for log output
				try {
					String safeBlabberUsername = URLEncoder.encode(blabberUsername, "UTF-8");
					logger.info("SELECT blab_name FROM users WHERE username = " + safeBlabberUsername);
				} catch (UnsupportedEncodingException e) {
					logger.info("SELECT blab_name FROM users WHERE username = [encoded]");
				}
				try (ResultSet rs = sqlStatement.executeQuery()) {
					rs.next();

					/* START EXAMPLE VULNERABILITY */
					String event = username + " started listening to " + blabberUsername + " (" + rs.getString(1) + ")";
					// Use PreparedStatement to prevent SQL injection
					String insertQuery = "INSERT INTO users_history (blabber, event) VALUES (?, ?)";
					try (PreparedStatement historyStatement = connect.prepareStatement(insertQuery)) {
						historyStatement.setString(1, username);
						historyStatement.setString(2, event);
						// Sanitize for log output
						try {
							String safeUsername = URLEncoder.encode(username, "UTF-8");
							String safeEvent = URLEncoder.encode(event, "UTF-8");
							logger.info("INSERT INTO users_history (blabber, event) VALUES (" + safeUsername + ", " + safeEvent + ")");
						} catch (UnsupportedEncodingException e) {
							logger.info("INSERT INTO users_history (blabber, event) VALUES ([encoded], [encoded])");
						}
						historyStatement.execute();
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
