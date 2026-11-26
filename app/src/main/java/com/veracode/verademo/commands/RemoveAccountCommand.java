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

public class RemoveAccountCommand implements BlabberCommand {
	private static final Logger logger = LogManager.getLogger("VeraDemo:RemoveAccountCommand");

	private Connection connect;

	public RemoveAccountCommand(Connection connect, String username) {
		super();
		this.connect = connect;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.veracode.verademo.commands.Command#execute()
	 */
	@Override
	public void execute(String blabberUsername) {
		String sqlQuery = "DELETE FROM listeners WHERE blabber=? OR listener=?;";
		logger.info(sqlQuery);
		PreparedStatement action;
		try {
			// Sanitize username for logging to prevent log injection
			String safeUsername = URLEncoder.encode(blabberUsername, "UTF-8");

			action = connect.prepareStatement(sqlQuery);

			action.setString(1, blabberUsername);
			action.setString(2, blabberUsername);
			action.execute();

			// Use PreparedStatement to prevent SQL injection and try-with-resources to prevent resource leaks
			sqlQuery = "SELECT blab_name FROM users WHERE username = ?";
			try (PreparedStatement selectStmt = connect.prepareStatement(sqlQuery);
			     PreparedStatement insertStmt = connect.prepareStatement("INSERT INTO users_history (blabber, event) VALUES (?, ?)");
			     PreparedStatement deleteStmt = connect.prepareStatement("DELETE FROM users WHERE username = ?")) {

				selectStmt.setString(1, blabberUsername);
				logger.info("SELECT blab_name FROM users WHERE username = " + safeUsername);
				try (ResultSet result = selectStmt.executeQuery()) {
					result.next();

					/* START EXAMPLE VULNERABILITY */
					String event = "Removed account for blabber " + result.getString(1);
					insertStmt.setString(1, blabberUsername);
					insertStmt.setString(2, event);
					logger.info("INSERT INTO users_history (blabber, event) VALUES (" + safeUsername + ", " + event + ")");
					insertStmt.execute();

					deleteStmt.setString(1, blabberUsername);
					logger.info("DELETE FROM users WHERE username = " + safeUsername);
					deleteStmt.execute();
					/* END EXAMPLE VULNERABILITY */
				}
			}

		} catch (SQLException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}
}
