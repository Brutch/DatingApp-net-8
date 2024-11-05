using System;
using Microsoft.AspNetCore.SignalR;

namespace API.DTOs;

public class LoginDTO
{
public required string Username { get; set; }
public required string Password { get; set;}
}
