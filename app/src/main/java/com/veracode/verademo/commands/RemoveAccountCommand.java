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
			// Sanitize username for logging
			String safeUsername = URLEncoder.encode(blabberUsername, "UTF-8");

			action = connect.prepareStatement(sqlQuery);

			action.setString(1, blabberUsername);
			action.setString(2, blabberUsername);
			action.execute();

			sqlQuery = "SELECT blab_name FROM users WHERE username = ?";
			try (PreparedStatement sqlStatement = connect.prepareStatement(sqlQuery)) {
				sqlStatement.setString(1, blabberUsername);
				logger.info("SELECT blab_name FROM users WHERE username = " + safeUsername);
				try (ResultSet result = sqlStatement.executeQuery()) {
					result.next();

					/* START EXAMPLE VULNERABILITY */
					String event = "Removed account for blabber " + result.getString(1);
					sqlQuery = "INSERT INTO users_history (blabber, event) VALUES (?, ?)";
					try (PreparedStatement insertStatement = connect.prepareStatement(sqlQuery)) {
						insertStatement.setString(1, blabberUsername);
						insertStatement.setString(2, event);
						logger.info("INSERT INTO users_history (blabber, event) VALUES (" + safeUsername + ", " + URLEncoder.encode(event, "UTF-8") + ")");
						insertStatement.execute();
					}

					sqlQuery = "DELETE FROM users WHERE username = ?";
					try (PreparedStatement deleteStatement = connect.prepareStatement(sqlQuery)) {
						deleteStatement.setString(1, blabberUsername);
						logger.info("DELETE FROM users WHERE username = " + safeUsername);
						deleteStatement.execute();
					}
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
