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

			// Use PreparedStatement for SELECT query to prevent SQL injection
			sqlQuery = "SELECT blab_name FROM users WHERE username = ?";
			// Sanitize query for logging to prevent log injection
			try {
				logger.info(URLEncoder.encode(sqlQuery, "UTF-8"));
			} catch (UnsupportedEncodingException e) {
				logger.info(sqlQuery);
			}
			try (PreparedStatement selectStatement = connect.prepareStatement(sqlQuery)) {
				selectStatement.setString(1, blabberUsername);
				try (ResultSet result = selectStatement.executeQuery()) {
					result.next();

					/* START EXAMPLE VULNERABILITY */
					String event = username + " started listening to " + blabberUsername + " (" + result.getString(1) + ")";
					// Use PreparedStatement for INSERT query to prevent SQL injection
					sqlQuery = "INSERT INTO users_history (blabber, event) VALUES (?, ?)";
					// Sanitize query for logging to prevent log injection
					try {
						logger.info(URLEncoder.encode(sqlQuery, "UTF-8"));
					} catch (UnsupportedEncodingException e) {
						logger.info(sqlQuery);
					}
					try (PreparedStatement insertStatement = connect.prepareStatement(sqlQuery)) {
						insertStatement.setString(1, username);
						insertStatement.setString(2, event);
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
